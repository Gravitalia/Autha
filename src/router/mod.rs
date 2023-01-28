pub mod create;
pub mod login;
pub mod users;
use warp::reply::{WithStatus, Json};

/// Create message error easier
fn err(message: String) -> WithStatus<Json> {
    warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: true,
            message,
        }
    ),
    warp::http::StatusCode::BAD_REQUEST)
}

/// Return an error with rate limit informations
fn rate() -> WithStatus<Json> {
    warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: true,
            message: "Too many requests".to_string(),
        }
    ),
    warp::http::StatusCode::TOO_MANY_REQUESTS)
}