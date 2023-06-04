use crate::{database::{get_user, mem::{set, del, SetValue}, cassandra::{update_user, query}}, helpers};
use crate::helpers::{crypto::{encrypt, hash}, request::delete_account};
use crate::model::{user::User, error::Error};
use warp::reply::{WithStatus, Json};
use super::suspend::suspend_user;
use anyhow::Result;
use regex::Regex;

lazy_static! {
    static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    static ref BIRTH: Regex = Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

/// Handle GET users route
pub fn get(vanity: String, requester: String) -> WithStatus<Json> {
    let user = match get_user(vanity.clone(), requester) {
        Ok(d) => d,
        Err(_) => {
            return warp::reply::with_status(warp::reply::json(
                &Error {
                    error: true,
                    message: "Unknown user".to_string()
                }
            ), warp::http::StatusCode::NOT_FOUND);
        }
    };

    if user.vanity.is_empty() {
        warp::reply::with_status(warp::reply::json(
            &Error {
                error: true,
                message: "Unknown user".to_string()
            }
        ), warp::http::StatusCode::NOT_FOUND)
    } else if user.deleted {
        warp::reply::with_status(warp::reply::json(
            &User {
                username: "Deleted user".to_string(),
                vanity,
                avatar: None,
                bio: None,
                email: None,
                birthdate: None,
                verified: false,
                deleted: true,
                flags: 0,
            }
        ), warp::http::StatusCode::OK)
    } else {
        let _ = set(vanity, SetValue::Characters(serde_json::to_string(&user).unwrap_or_default()));

        warp::reply::with_status(warp::reply::json(
            &user
        ), warp::http::StatusCode::OK)
    }
}

/// Handle PATCH users route and let users modifie their profile
pub async fn patch(vanity: String, body: crate::model::body::UserPatch) -> Result<WithStatus<Json>> {
    let res = match query("SELECT username, avatar, bio, email, password FROM accounts.users WHERE vanity = ?", vec![vanity.clone()]) {
        Ok(x) => x.get_body()?.as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return Ok(warp::reply::with_status(warp::reply::json(
                &Error {
                    error: true,
                    message: "Unknown user".to_string()
                }
            ), warp::http::StatusCode::NOT_FOUND));
        }
    };

    let mut is_psw_valid: bool = false;
    if body.password.is_some() {
        if crate::helpers::crypto::hash_test(std::str::from_utf8(&res[0][4].clone().into_plain().unwrap_or_default()[..]).unwrap(), body.password.unwrap_or_default().as_ref()) {
            is_psw_valid = true;
        } else {
            return Ok(super::err("Invalid password".to_string()));
        }
    }

    let mut username = std::str::from_utf8(&res[0][0].clone().into_plain().unwrap_or_default()[..])?.to_string();
    let mut avatar = if res[0][1].clone().into_plain().is_some() { Some(std::str::from_utf8(&res[0][1].clone().into_plain().unwrap_or_default()[..])?.to_string()) } else { None };
    let mut bio: Option<String> = None;
    let mut email = std::str::from_utf8(&res[0][3].clone().into_plain().unwrap_or_default()[..])?.to_string();
    let mut birthdate: Option<String> = None;
    let phone: Option<String> = None;

    // Change username
    if let Some(u) = body.username {
        if u.len() > 25 {
            return Ok(super::err("Invalid username".to_string()));
        } else {
            username = u;
        }
    }
    
    // Change bio
    if let Some(b) = body.bio {
        if b.len() > 160 {
            return Ok(super::err("Invalid bio".to_string()));
        } else if !b.is_empty() {
            bio = Some(b);
        }
    }

    // Change avatar
    if let Some(a) = body.avatar {
        if a.is_empty() {
            avatar = None;
        } else {
            if helpers::grpc::check_avatar(a.clone()).await? {
                return Ok(super::err("Avatar seems to be nsfw".to_string()));
            } else {
                avatar = Some(helpers::grpc::upload_avatar(a).await?);
            }
        }
    }

    // Change email
    if let Some(e) = body.email {
        if !is_psw_valid || !EMAIL.is_match(&e) {
            return Ok(super::err("Invalid email".to_string()));
        } else {
            // Hash email
            let hashed_email = helpers::crypto::fpe_encrypt(e.encode_utf16().collect())?;

            // Check if email is already used
            let query_res = match query("SELECT vanity FROM accounts.users WHERE email = ?", vec![hashed_email.clone()]) {
                Ok(x) => x.get_body()?.into_rows().unwrap_or_default(),
                Err(_) => {
                    return Ok(super::err("Internal server error".to_string()));
                }
            };
            if !query_res.is_empty() {
                return Ok(super::err("Email already used".to_string()));
            }

            email = hashed_email;
        }
    }
    
    // Change birthdate
    if let Some(b) = body.birthdate {
        if !BIRTH.is_match(&b) {
            return Ok(super::err("Invalid birthdate".to_string()));
        } else {
            let dates: Vec<&str> = b.split('-').collect();
    
            if 13 > helpers::get_age(dates[0].parse::<i32>()?, dates[1].parse::<u32>()?, dates[2].parse::<u32>()?) as i32 {
                suspend_user(vanity, true)?;
                return Ok(super::err("Your account has been suspended: age".to_string()));
            } else {
                birthdate = Some(encrypt(b.as_bytes()));
            }
        }
    }
    
    // Change phone
    if let Some(_p) = body.phone {
        return Ok(super::err("Phones not implemented yet".to_string()));
    }

    // Change 2FA (mfa)
    if let Some(m) = body.mfa {
        if !is_psw_valid {
            return Ok(super::err("Invalid MFA".to_string()));
        } else {
            match query("UPDATE accounts.users SET mfa_code = ? WHERE vanity = ?", vec![encrypt(m.as_bytes()), vanity.clone()]) {
                Ok(_) => {},
                Err(_) => {
                    return Ok(super::err("Internal server error".to_string()));
                }
            };
        }
    }
    
    // Change password
    if let Some(np) = body.newpassword {
        if !is_psw_valid || !PASSWORD.is_match(&np) {
            return Ok(super::err("Invalid password".to_string()));
        } else {
            match query("UPDATE accounts.users SET password = ? WHERE vanity = ?", vec![hash(np.as_ref()), vanity.clone()]) {
                Ok(_) => {},
                Err(_) => {
                    return Ok(super::err("Internal server error".to_string()));
                }
            };
        }
    }

    match update_user(username, avatar, bio, birthdate, phone, email, vanity.clone()) {
        Ok(_) => {
            let _ = del(vanity);
            Ok(warp::reply::with_status(warp::reply::json(
                &Error {
                    error: false,
                    message: "OK".to_string()
                }
            ), warp::http::StatusCode::OK))
        },
        Err(_) => {
            Ok(super::err("Internal server error".to_string()))
        }
    }
}

/// Delete route for remove account from database
pub async fn delete(vanity: String, body: crate::model::body::Gdrp) -> Result<WithStatus<Json>> {
    let res = match query("SELECT password FROM accounts.users WHERE vanity = ?", vec![vanity.clone()]) {
        Ok(x) => x.get_body()?.as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return Ok(warp::reply::with_status(warp::reply::json(
                &Error {
                    error: true,
                    message: "Unknown user".to_string()
                }
            ), warp::http::StatusCode::NOT_FOUND));
        }
    };

    // Check if security token is valid
    match crate::helpers::request::check_turnstile(body.security_token).await {
        Ok(res) => {
            if !res {
                return Ok(crate::router::err("Invalid security_token".to_string()));
            }
        },
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    if !crate::helpers::crypto::hash_test(std::str::from_utf8(&res[0][0].clone().into_plain().unwrap_or_default()[..])?, body.password.as_ref()) {
        return Ok(super::err("Invalid password".to_string()));
    }

    for url in helpers::config_reader::read().services.iter().map(|s| s.to_owned()) {
        let _ = delete_account(url, vanity.clone()).await;
    }

    query(format!("UPDATE accounts.users SET deleted = true, expire_at = '{}' WHERE vanity = ?", (chrono::Utc::now()+chrono::Duration::days(30)).format("%Y-%m-%d+0000")), vec![vanity])?;

    Ok(warp::reply::with_status(warp::reply::json(
        &Error {
            error: false,
            message: "OK".to_string()
        }
    ), warp::http::StatusCode::OK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex() {
        assert!(EMAIL.is_match("foo@🏹.to"));
        assert!(PASSWORD.is_match("Test1234_"));
        assert!(BIRTH.is_match("2000-01-01"));
    }
}
