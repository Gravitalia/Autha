use crate::{database::{get_user, mem::set, mem::SetValue}, model::{user::User, error::Error}};
use warp::reply::{WithStatus, Json};

/// Handle GET users route
pub fn get(vanity: String) -> WithStatus<Json> {
    let user: User = match get_user(vanity.clone()) {
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
                username: "Account suspended".to_string(),
                vanity,
                avatar: None,
                bio: None,
                verified: false,
                deleted: true,
                flags: 0,
            }
        ), warp::http::StatusCode::OK)
    } else {
        let _ = set(vanity, SetValue::Characters(serde_json::to_string(&user).unwrap()));

        warp::reply::with_status(warp::reply::json(
            &user
        ), warp::http::StatusCode::OK)
    }
}