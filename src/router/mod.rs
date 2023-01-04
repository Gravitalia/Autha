pub mod create;
use warp::reply::{WithStatus, Json};

/// Create message error easier
fn err(message: String) -> WithStatus<Json> {
    warp::reply::with_status(warp::reply::json(
        &model::Error{
            error: true,
            message,
        }
    ),
    warp::http::StatusCode::BAD_REQUEST)
}