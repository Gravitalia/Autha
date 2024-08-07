use crate::helpers::queries::{CREATE_SALT, GET_USER};
use crate::model::user::User;
use anyhow::{bail, Result};
use crypto::hash::argon2::{argon2, check_argon2, Argon2Configuration};
use db::{
    broker::Broker,
    libscylla::{batch::Batch, IntoTypedRows},
    memcache::MemcachePool,
    scylla::Scylla,
};
use image_processor::{
    host::cloudinary::upload,
    resizer::{resize, Encode, Encoder, Lossy},
};
use std::{convert::Infallible, sync::Arc};
use tracing::{error, trace};
use warp::{reply::Reply, Rejection};

const IMAGE_WIDTH: u32 = 224;
const IMAGE_HEIGHT: u32 = 224;
const IMAGE_QUALITY: u8 = 60;

/// Get a user with its vanity via a cache or the database.
#[inline]
pub async fn get_user(
    scylla: &std::sync::Arc<Scylla>,
    memcached: &MemcachePool,
    vanity: &str,
) -> Result<User> {
    if let Some(cached) = memcached.get(vanity)? {
        Ok(serde_json::from_str::<User>(&cached[..])?)
    } else {
        let user = if let Some(rows) = scylla
            .connection
            .execute(GET_USER.get_or_init(|| unreachable!()), vec![vanity])
            .await?
            .rows
        {
            if rows.is_empty() {
                bail!("no user found")
            } else {
                rows.into_typed::<User>().collect::<Vec<_>>()[0].clone()?
            }
        } else {
            bail!("no user found")
        };

        // Save user into cache if not exists in it.
        memcached.set(vanity, serde_json::to_string(&user)?)?;

        Ok(user)
    }
}

/// Handle get user route.
/// This route allow using ID parameters as "@me" to get actual users.
pub async fn get(
    mut id: String,
    _: (),
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    token: Option<String>,
) -> Result<impl Reply, Infallible> {
    let mut is_jwt = false;
    let is_me = id == "@me";

    if id == "@me" {
        if let Some(tok) = token {
            id = match super::vanity_from_token(&scylla, &tok).await {
                Ok(data) => {
                    if let Some(scopes) = data.scopes {
                        if !scopes.iter().any(|s| *s == "identity") {
                            return Ok(super::err("insufficient_scope The request requires higher privileges than provided by the access token."));
                        }
                        is_jwt = true;
                    }

                    data.vanity
                },
                Err(error) => {
                    error!("Cannot retrive user token: {}", error);
                    return Ok(super::err(super::INVALID_TOKEN));
                },
            };
        } else {
            return Ok(super::err(super::MISSING_AUTHORIZATION_HEADER));
        }
    }

    let user = get_user(&scylla, &memcached, &id).await.unwrap_or_default();

    if user.vanity.is_empty() {
        return Ok(super::err("User not found"));
    } else if user.deleted {
        return Ok(warp::reply::with_status(
            warp::reply::json(&User {
                username: "Deleted User".to_string(),
                vanity: user.vanity,
                avatar: None,
                bio: None,
                email: None,
                birthdate: None,
                phone: None,
                verified: false,
                deleted: true,
                flags: 0,
            }),
            warp::http::StatusCode::OK,
        ));
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&User {
            username: user.username,
            vanity: user.vanity,
            avatar: user.avatar,
            bio: user.bio,
            email: if is_jwt || !is_me {
                None
            } else {
                Some(
                    crypto::decrypt::format_preserving_encryption(
                        hex::decode(user.email.unwrap_or_default())
                            .unwrap_or_default()
                            .chunks_exact(1)
                            .map(|chunk| u16::from_le_bytes([chunk[0], 0]))
                            .collect(),
                    )
                    .unwrap_or_default(),
                )
            },
            birthdate: None,
            phone: None,
            verified: user.verified,
            deleted: user.deleted,
            flags: user.flags,
        }),
        warp::http::StatusCode::OK,
    ))
}

/// Handle users modifications route.
#[allow(unused)]
pub async fn update(
    _: (),
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    broker: Arc<Broker>,
    token: String,
    body: crate::model::body::UserPatch,
) -> Result<impl Reply, Rejection> {
    let vanity = match crate::helpers::token::get(&scylla, &token).await {
        Ok(vanity) => vanity,
        Err(error) => {
            error!("Cannot retrive user token: {}", error);
            return Ok(super::err(super::INVALID_TOKEN));
        },
    };

    let rows = scylla
        .connection
        .query(
            "SELECT username, email, password, avatar, bio FROM accounts.users WHERE vanity = ?",
            vec![&vanity],
        )
        .await
        .map_err(|_| crate::router::Errors::Unspecified)?
        .rows_typed::<(String, String, String, Option<String>, Option<String>)>()
        .map_err(|_| crate::router::Errors::Unspecified)?
        .collect::<Vec<_>>();

    let (mut username, mut email, password, mut avatar, mut bio) =
        rows[0].clone().unwrap_or_default();
    let mut birthdate: Option<String> = None;
    let mut phone: Option<String> = None;

    let mut is_psw_valid = false;
    if let Some(psw) = body.password {
        if check_argon2(
            std::env::var("KEY")
                .unwrap_or_else(|_| "KEY".to_string())
                .as_bytes(),
            password,
            psw.as_bytes(),
            Some(vanity.as_bytes()),
        )
        .map_err(|_| crate::router::Errors::Unspecified)?
        {
            is_psw_valid = true;
        } else {
            return Ok(crate::router::err(super::INVALID_PASSWORD));
        }
    }

    // Prepare the query to be faster if user set both phone, birthdate and MFA.
    // It will avoid database to make a query pasing.
    let insert_salt_query = if let Some(query) = CREATE_SALT.get() {
        query.clone()
    } else {
        error!("Prepared queries do not appear to be initialized.");
        return Err(crate::router::Errors::Unspecified.into());
    };

    // New batch to perform multiple requests at the same time.
    let mut batch = Batch::default();
    let mut batch_values: Vec<(String, String)> = Vec::new();

    // Update username (firstname and lastname).
    if let Some(u) = body.username {
        if u.len() > 25 {
            return Ok(crate::router::err(super::INVALID_USERNAME));
        } else {
            username = u;
        }
    }

    // Update biography.
    if let Some(b) = body.bio {
        if b.len() > 160 {
            return Ok(crate::router::err("Invalid bio"));
        } else if !b.is_empty() {
            bio = Some(b);
        }
    }

    // Update avatar.
    if let Some(a) = body.avatar {
        if a.is_empty() {
            avatar = None;
        } else {
            let config: crate::model::config::Config =
                crate::helpers::config::read();

            if let Some(hoister) = config.image_delivery {
                let resized_img = resize(
                    &a,
                    Encoder {
                        encoder: Encode::Lossy(Lossy::Jpeg(IMAGE_QUALITY)),
                        width: Some(IMAGE_WIDTH),
                        height: Some(IMAGE_HEIGHT),
                        speed: None,
                    },
                )
                .map_err(|_| crate::router::Errors::Unspecified)?;
                let credentials = match hoister.platform {
                    crate::model::config::Platforms::Cloudinary => {
                        image_processor::host::cloudinary::Credentials {
                            key: hoister.key,
                            cloud_name: hoister.cloud_name.unwrap_or_default(),
                            secret: hoister.secret,
                        }
                    },
                };

                if let Some(remini_url) = config.remini_url {
                    if crate::helpers::machine_learning::is_nude(
                        remini_url,
                        &resized_img,
                    )
                    .await
                    .map_err(|_| crate::router::Errors::Unspecified)?
                    {
                        return Ok(crate::router::err(
                            "Avatar appears to contain nudity",
                        ));
                    } else {
                        avatar = Some(
                            upload(credentials, &resized_img).await.map_err(
                                |_| crate::router::Errors::Unspecified,
                            )?,
                        );
                    }
                } else {
                    avatar = Some(
                        upload(credentials, &resized_img)
                            .await
                            .map_err(|_| crate::router::Errors::Unspecified)?,
                    );
                }
            }
        }
    }

    // Update email.
    if let Some(e) = body.email {
        if !is_psw_valid || !crate::router::create::EMAIL.is_match(&e) {
            return Ok(crate::router::err(super::INVALID_EMAIL));
        } else {
            let hashed_email = crypto::encrypt::format_preserving_encryption(
                std::env::var("AES256_KEY")
                    .unwrap_or_else(|_| super::DEFAULT_AES_KEY.to_string()),
                e.encode_utf16().collect(),
            )
            .map_err(|_| crate::router::Errors::Unspecified)?;

            // Check if email is already in use.
            if !scylla
                .connection
                .query(
                    "SELECT vanity FROM accounts.users WHERE email = ?",
                    vec![&hashed_email],
                )
                .await
                .map_err(|_| crate::router::Errors::Unspecified)?
                .rows
                .unwrap_or_default()
                .is_empty()
            {
                return Ok(crate::router::err("Email already used"));
            }

            // Otherwise, set it.
            email = hashed_email;
        }
    }

    // Update birthdate.
    if let Some(birth) = body.birthdate {
        if !crate::router::create::BIRTH.is_match(&birth) {
            return Ok(crate::router::err(super::INVALID_BIRTHDATE));
        } else {
            let dates: Vec<&str> = birth.split('-').collect();

            if 13
                > crate::helpers::get_age(
                    dates[0].parse::<i16>().unwrap_or_default(),
                    dates[1].parse::<i8>().unwrap_or_default(),
                    dates[2].parse::<i8>().unwrap_or_default(),
                )
                .map_err(|_| crate::router::Errors::Unspecified)?
            {
                return Ok(crate::router::err(super::INVALID_BIRTHDATE));
            } else {
                let (nonce, encrypted) =
                    crypto::encrypt::chacha20_poly1305(birth.into())
                        .map_err(|_| crate::router::Errors::Unspecified)?;
                let uuid = uuid::Uuid::new_v4();

                batch.append_statement(insert_salt_query.clone());
                batch_values.push((uuid.to_string(), nonce));

                // Set primary key (to get nonce) and encrypted birthdate.
                birthdate = Some(format!("{}//{}", uuid, encrypted));
            }
        }
    }

    // Update phone.
    if let Some(number) = body.phone {
        if !crate::router::create::PHONE.is_match(&number) {
            return Ok(super::err(super::INVALID_PHONE));
        } else {
            let (nonce, encrypted) =
                crypto::encrypt::chacha20_poly1305(number.into())
                    .map_err(|_| crate::router::Errors::Unspecified)?;
            let uuid = uuid::Uuid::new_v4();

            batch.append_statement(insert_salt_query.clone());
            batch_values.push((uuid.to_string(), nonce));

            // Set primary key (to get nonce) and encrypted phone.
            phone = Some(format!("{}//{}", uuid, encrypted));
        }
    }

    // Change 2FA (MFA).
    if let Some(mfa) = body.mfa {
        if !is_psw_valid {
            return Ok(crate::router::err(super::INVALID_PASSWORD));
        } else {
            let (nonce, encrypted) =
                crypto::encrypt::chacha20_poly1305(mfa.into())
                    .map_err(|_| crate::router::Errors::Unspecified)?;
            let uuid = uuid::Uuid::new_v4();

            batch.append_statement(insert_salt_query);
            batch_values.push((uuid.to_string(), nonce));

            batch.append_statement(
                "UPDATE accounts.users SET mfa_code = ? WHERE vanity = ?;",
            );
            batch_values
                .push((format!("{}//{}", uuid, encrypted), vanity.clone()));
        }
    }

    // Change password
    if let Some(np) = body.new_password {
        if !is_psw_valid || !crate::router::create::PASSWORD.is_match(&np) {
            return Ok(crate::router::err(super::INVALID_PASSWORD));
        } else {
            let argon_config = Argon2Configuration {
                memory_cost: std::env::var("MEMORY_COST")
                    .unwrap_or_default()
                    .parse::<u32>()
                    .unwrap_or(262144),
                round: std::env::var("ROUND")
                    .unwrap_or_default()
                    .parse::<u32>()
                    .unwrap_or(1),
                lanes: 8,
                secret: std::env::var("KEY")
                    .unwrap_or_else(|_| "KEY".to_string()),
                hash_length: std::env::var("HASH_LENGTH")
                    .unwrap_or_default()
                    .parse::<u32>()
                    .unwrap_or(16),
            };

            batch.append_statement(
                "UPDATE accounts.users SET password = ? WHERE vanity = ?",
            );
            batch_values.push((
                argon2(argon_config, np.as_bytes(), Some(vanity.as_bytes()))
                    .map_err(|_| crate::router::Errors::Unspecified)?,
                vanity.clone(),
            ));
        }
    }

    // Prepare a batch to take advantage of good load balancing.
    let prepared_batch = scylla
        .connection
        .prepare_batch(&batch)
        .await
        .map_err(|_| crate::router::Errors::Unspecified)?;
    scylla
        .connection
        .batch(&prepared_batch, batch_values)
        .await
        .map_err(|_| crate::router::Errors::Unspecified)?;

    match scylla
    .connection.
    query(
        "UPDATE accounts.users SET username = ?, avatar = ?, bio = ?, birthdate = ?, phone = ?, email = ? WHERE vanity = ?",
        (
            &username,
            &avatar,
            &bio,
            &birthdate,
            &phone,
            &email,
            &vanity,
        )
    ).await {
        Ok(_) => {
            trace!("User {} modified his profile.", vanity);

            #[cfg(any(feature = "kafka", feature = "rabbitmq"))]
            {
                use crate::model::broker::Message;
                use chrono::Utc;
                use crypto::random_string;

                let topic = format!("{}.autha.user", std::env::var("SERVICE_NAME").unwrap_or("gravitalia".to_string()));
                let new_user = serde_json::to_string(
                    &Message {
                        id: random_string(36),
                        datacontenttype: "application/json; charset=utf-8".to_string(),
                        data: User {
                            username,
                            vanity: vanity.clone(),
                            avatar,
                            bio,
                            email: None,
                            birthdate: None,
                            phone: None,
                            verified: false,
                            deleted: false,
                            flags: 0,
                        },
                        source: format!("//autha.gravitalia.com/users/{}", vanity),
                        specversion: "1.0".to_string(),
                        time: Some(Utc::now().to_rfc3339()),
                        r#type: "com.gravitalia.autha.user.v1.userModified".to_string(),
                    }
                ).map_err(|_| crate::router::Errors::Unspecified)?;

                match <std::sync::Arc<Broker> as Into<Broker>>::into(broker) {
                    #[cfg(feature = "kafka")]
                    Broker::Kafka(func) => func.publish(&topic, &new_user).map_err(|_| crate::router::Errors::Unspecified)?,
                    #[cfg(feature = "rabbitmq")]
                    Broker::RabbitMQ(func) => func.publish(&topic, &new_user).await.map_err(|_| crate::router::Errors::Unspecified)?,
                    // Won't happend.
                    _ => {},
                }
            }

            // Delete cached user.
            memcached.delete(vanity).map_err(|_| crate::router::Errors::Unspecified)?;

            Ok(warp::reply::with_status(
                warp::reply::json(&crate::model::error::Error {
                    error: false,
                    message: "OK".to_string(),
                }),
                warp::http::StatusCode::OK,
            ))
        }
        Err(_) => Ok(crate::router::err(super::INTERNAL_SERVER_ERROR)),
    }
}
