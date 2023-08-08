use crate::database::{
    get_user,
    mem::{set, SetValue},
};
use crate::helpers;
use crate::model::{error::Error, user::User};
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

/// Handle GET users route
pub async fn get(
    scylla: Arc<scylla::Session>,
    memcached: Arc<memcache::Client>,
    id: String,
    token: Option<String>,
) -> WithStatus<Json> {
    println!("{}", id == "@me");
    println!("{}", token.is_some());
    println!(
        "{}",
        crate::router::TOKEN.is_match(token.as_deref().unwrap_or_default())
    );
    println!(
        "{}",
        id == "@me"
            && token.is_some()
            && crate::router::TOKEN
                .is_match(token.as_deref().unwrap_or_default())
    );

    // Check authorization
    let requester: String;
    let vanity = if id == "@me"
        && token.is_some()
        && crate::router::TOKEN.is_match(token.as_deref().unwrap_or_default())
    {
        let oauth = match helpers::jwt::get_jwt(token.unwrap_or_default()) {
            Ok(d) => {
                if d.claims.exp
                    <= std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                {
                    return warp::reply::with_status(
                        warp::reply::json(&Error {
                            error: true,
                            message: "Invalid token".to_string(),
                        }),
                        warp::http::StatusCode::UNAUTHORIZED,
                    );
                }

                d.claims
            }
            Err(_) => {
                return warp::reply::with_status(
                    warp::reply::json(&Error {
                        error: true,
                        message: "Invalid token".to_string(),
                    }),
                    warp::http::StatusCode::UNAUTHORIZED,
                );
            }
        };

        requester = if oauth.scope.contains(&"private".to_string()) {
            oauth.sub.clone()
        } else {
            "".to_string()
        };

        oauth.sub
    } else {
        let middelware_res =
            crate::router::middleware(Arc::clone(&scylla), token, &id)
                .await
                .unwrap_or_else(|_| "Invalid".to_string());

        if middelware_res != "Invalid" && middelware_res != "Suspended" {
            let vanity = middelware_res.to_lowercase();

            requester = if id == "@me" {
                vanity.clone()
            } else {
                "".to_string()
            };

            vanity
        } else {
            return warp::reply::with_status(
                warp::reply::json(&Error {
                    error: true,
                    message: "Invalid token".to_string(),
                }),
                warp::http::StatusCode::UNAUTHORIZED,
            );
        }
    };

    // Get user
    let (from_mem, user) = match get_user(
        scylla,
        Some(Arc::clone(&memcached)),
        vanity.clone(),
        requester.clone(),
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            eprintln!("(get) Cannot get user: {e}");
            return warp::reply::with_status(
                warp::reply::json(&Error {
                    error: true,
                    message: "Unknown user".to_string(),
                }),
                warp::http::StatusCode::NOT_FOUND,
            );
        }
    };

    if user.vanity.is_empty() {
        warp::reply::with_status(
            warp::reply::json(&Error {
                error: true,
                message: "Unknown user".to_string(),
            }),
            warp::http::StatusCode::NOT_FOUND,
        )
    } else if user.deleted {
        warp::reply::with_status(
            warp::reply::json(&User {
                username: "Deleted user".to_string(),
                vanity,
                avatar: None,
                bio: None,
                email: None,
                birthdate: None,
                verified: false,
                deleted: true,
                flags: 0,
                phone: None,
                password: None,
            }),
            warp::http::StatusCode::OK,
        )
    } else {
        if !from_mem && vanity != requester && user.email.is_none() {
            let _ = set(
                memcached,
                vanity,
                SetValue::Characters(
                    serde_json::to_string(&user).unwrap_or_default(),
                ),
            );
        }

        warp::reply::with_status(
            warp::reply::json(&user),
            warp::http::StatusCode::OK,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::router::*;

    #[test]
    fn test_regex() {
        assert!(TOKEN.is_match("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    }
}
