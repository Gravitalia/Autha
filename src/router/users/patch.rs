use crate::helpers::crypto::{encrypt, hash};
use crate::model::error::Error;
use crate::router::suspend::suspend_user;
use crate::{
    database::{
        mem::{del, MemPool},
        nats::publish,
        scylla::query,
    },
    helpers,
};
use anyhow::{anyhow, Result};
use warp::reply::{Json, WithStatus};

// Define queries
const GET_MUTABLE_VALUES: &str = "SELECT username, avatar, bio, email, password FROM accounts.users WHERE vanity = ?;";
const CHECK_EMAIL: &str = "SELECT vanity FROM accounts.users WHERE email = ?;";
const UPDATE_MFA: &str =
    "UPDATE accounts.users SET mfa_code = ? WHERE vanity = ?;";
const UPDATE_PASSWORD: &str =
    "UPDATE accounts.users SET password = ? WHERE vanity = ?;";

/// Handle PATCH users route and let users modifie their profile
pub async fn patch(
    scylla: std::sync::Arc<scylla::Session>,
    memcached: MemPool,
    nats: Option<async_nats::jetstream::Context>,
    token: String,
    body: crate::model::body::UserPatch,
) -> Result<WithStatus<Json>> {
    let middelware_res =
        crate::router::middleware(&scylla, Some(token), "Invalid")
            .await
            .unwrap_or_else(|_| "Invalid".to_string());

    let vanity: String =
        if middelware_res != "Invalid" && middelware_res != "Suspended" {
            middelware_res.to_lowercase()
        } else {
            return Ok(warp::reply::with_status(
                warp::reply::json(&crate::model::error::Error {
                    error: true,
                    message: "Invalid token".to_string(),
                }),
                warp::http::StatusCode::UNAUTHORIZED,
            ));
        };

    let query_res = query(&scylla, GET_MUTABLE_VALUES, vec![vanity.clone()])
        .await?
        .rows
        .unwrap_or_default();

    let mut is_psw_valid: bool = false;
    if body.password.is_some() {
        if crate::helpers::crypto::hash_test(
            query_res[0].columns[4]
                .as_ref()
                .ok_or_else(|| anyhow!("No reference"))?
                .as_text()
                .ok_or_else(|| anyhow!("Can't convert to string"))?,
            body.password.unwrap_or_default().as_ref(),
        ) {
            is_psw_valid = true;
        } else {
            return Ok(crate::router::err("Invalid password".to_string()));
        }
    }

    // Set default values
    let mut username = query_res[0].columns[0]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_text()
        .ok_or_else(|| anyhow!("Can't convert to string"))?
        .to_string();

    let mut avatar = if query_res[0].columns[1].is_none() {
        None
    } else {
        let avatar = query_res[0].columns[1]
            .as_ref()
            .ok_or_else(|| anyhow!("No reference"))?
            .as_text()
            .ok_or_else(|| anyhow!("Can't convert to string"))?
            .to_string();
        if avatar.is_empty() {
            None
        } else {
            Some(avatar)
        }
    };

    let mut bio: Option<String> = if query_res[0].columns[2].is_none() {
        None
    } else {
        let bio = query_res[0].columns[2]
            .as_ref()
            .ok_or_else(|| anyhow!("No reference"))?
            .as_text()
            .ok_or_else(|| anyhow!("Can't convert to string"))?
            .to_string();
        if bio.is_empty() {
            None
        } else {
            Some(bio)
        }
    };

    let mut email = query_res[0].columns[3]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_text()
        .ok_or_else(|| anyhow!("Can't convert to string"))?
        .to_string();

    let mut birthdate: Option<String> = None;

    let phone: Option<String> = None;

    // Change username
    if let Some(u) = body.username {
        if u.len() > 25 {
            return Ok(crate::router::err("Invalid username".to_string()));
        } else {
            username = u;
        }
    }

    // Change bio
    if let Some(b) = body.bio {
        if b.len() > 160 {
            return Ok(crate::router::err("Invalid bio".to_string()));
        } else if !b.is_empty() {
            bio = Some(b);
        }
    }

    // Change avatar
    if let Some(a) = body.avatar {
        if a.is_empty() {
            avatar = None;
        } else if helpers::grpc::check_avatar(a.clone()).await? {
            return Ok(crate::router::err(
                "Avatar seems to be nsfw".to_string(),
            ));
        } else {
            avatar = Some(helpers::grpc::upload_avatar(a).await?);
        }
    }

    // Change email
    if let Some(e) = body.email {
        if !is_psw_valid || !crate::router::create::EMAIL.is_match(&e) {
            return Ok(crate::router::err("Invalid email".to_string()));
        } else {
            // Hash email
            let hashed_email =
                helpers::crypto::fpe_encrypt(e.encode_utf16().collect())?;

            // Check if email is already used
            let query_res =
                query(&scylla, CHECK_EMAIL, vec![hashed_email.clone()])
                    .await?
                    .rows
                    .unwrap_or_default();

            if !query_res.is_empty() {
                return Ok(crate::router::err(
                    "Email already used".to_string(),
                ));
            }

            email = hashed_email;
        }
    }

    // Change birthdate
    if let Some(b) = body.birthdate {
        if !crate::router::create::BIRTH.is_match(&b) {
            return Ok(crate::router::err("Invalid birthdate".to_string()));
        } else {
            let dates: Vec<&str> = b.split('-').collect();

            if 13
                > helpers::get_age(
                    dates[0].parse::<i32>()?,
                    dates[1].parse::<u32>()?,
                    dates[2].parse::<u32>()?,
                ) as i32
            {
                suspend_user(&scylla, vanity, true).await?;
                return Ok(crate::router::err(
                    "Your account has been suspended: age".to_string(),
                ));
            } else {
                birthdate = Some(encrypt(&scylla, b.as_bytes()).await);
            }
        }
    }

    // Change phone
    if let Some(_p) = body.phone {
        return Ok(crate::router::err(
            "Phones not implemented yet".to_string(),
        ));
    }

    // Change 2FA (mfa)
    if let Some(m) = body.mfa {
        if !is_psw_valid {
            return Ok(crate::router::err("Invalid MFA".to_string()));
        } else {
            query(
                &scylla,
                UPDATE_MFA,
                vec![encrypt(&scylla, m.as_bytes()).await, vanity.clone()],
            )
            .await?;
        }
    }

    // Change password
    if let Some(np) = body.newpassword {
        if !is_psw_valid || !crate::router::create::PASSWORD.is_match(&np) {
            return Ok(crate::router::err("Invalid password".to_string()));
        } else {
            query(
                &scylla,
                UPDATE_PASSWORD,
                vec![hash(np.as_ref()), vanity.clone()],
            )
            .await?;
        }
    }

    match query(
        &scylla,
        "UPDATE accounts.users SET username = ?, avatar = ?, bio = ?, birthdate = ?, phone = ?, email = ? WHERE vanity = ?;",
        (
            username.clone(),
            avatar.clone(),
            bio.clone(),
            birthdate,
            phone,
            email,
            vanity.clone()
        )
    ).await {
        Ok(_) => {
            if let Some(conn) = nats {
                match publish(conn, crate::model::user::UpdatedUser {
                    username,
                    vanity: vanity.clone(),
                    avatar,
                    bio
                }).await {
                    Ok(_) => {},
                    Err(e) => {
                        eprintln!("(patch) cannot send modified user: {}", e);
                    }
                }
            }

            let _ = del(&memcached, vanity);
            Ok(warp::reply::with_status(
                warp::reply::json(&Error {
                    error: false,
                    message: "OK".to_string(),
                }),
                warp::http::StatusCode::OK,
            ))
        }
        Err(_) => Ok(crate::router::err("Internal server error".to_string())),
    }
}
