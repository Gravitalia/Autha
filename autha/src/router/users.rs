use anyhow::Result;
use db::memcache::{MemcacheManager, MemcachePool};
use db::model::User;
use db::scylla::{Scylla, ScyllaManager};
use warp::reply::{Json, WithStatus};

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
        let user = scylla.get_user(vanity).await?;

        // Save user into cache if not exists in it.
        memcached.set(vanity, serde_json::to_string(&user)?)?;

        Ok(user)
    }
}

/// Handle get user route.
/// This route allow using ID parameters as "@me" to get actual users.
pub async fn get(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    mut id: String,
    token: Option<String>,
) -> Result<WithStatus<Json>> {
    let mut is_jwt = false;
    let is_me = id == "@me";

    if id == "@me" {
        if let Some(tok) = token {
            id = match crate::helpers::token::get(&scylla, &tok).await {
                Ok(vanity) => vanity,
                Err(error) => {
                    log::error!("Cannot retrive user token: {}", error);

                    // If no user token has been found, try with JWT.
                    // JWT is used for OAuth2.
                    match crate::helpers::token::get_jwt_data(&tok) {
                        Ok(vanity) => {
                            is_jwt = true;
                            vanity.0
                        }
                        Err(_) => {
                            return Ok(super::err(super::INVALID_TOKEN));
                        }
                    }
                }
            }
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
                Some(crypto::decrypt::format_preserving_encryption(
                    hex::decode(user.email.unwrap_or_default())?
                        .chunks_exact(1)
                        .map(|chunk| u16::from_le_bytes([chunk[0], 0]))
                        .collect(),
                )?)
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
