pub mod suspend;
pub mod create;
pub mod users;
pub mod login;

use warp::reply::{WithStatus, Json};
use regex::Regex;

lazy_static! {
    static ref TOKEN: Regex = Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)").unwrap();
}

/// Check if a token is valid and if have a real user behind (not suspended)
async fn middleware(scylla: std::sync::Arc<scylla::Session>, token: Option<String>, fallback: &str) -> anyhow::Result<String> {
    match token {
        Some(ntoken) if fallback == "@me" => {
            match crate::helpers::token::check(scylla, ntoken).await {
                Ok(data) => {
                    return Ok(data);
                },
                Err(e) => {
                    if e.to_string() == *"revoked" {
                        return Ok("Suspended".to_string());
                    } else if e.to_string() == *"expired" {
                        return Ok("Invalid".to_string());
                    }
                }
            }
            Ok("Invalid".to_string())
        }
        None if fallback == "@me" => Ok("Invalid".to_string()),
        _ => Ok(fallback.to_string()),
    }
}

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
            message: "Rate limit exceeded".to_string(),
        }
    ),
    warp::http::StatusCode::TOO_MANY_REQUESTS)
}