pub mod create;
pub mod login;
pub mod oauth;
pub mod suspend;
pub mod users;

use regex::Regex;
use warp::reply::{Json, WithStatus};

lazy_static! {
    static ref TOKEN: Regex =
        Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)")
            .unwrap();
}

/// Check if a token is valid and if have a real user behind (not suspended)
async fn middleware(
    scylla: &std::sync::Arc<scylla::Session>,
    token: Option<String>,
    fallback: &str,
) -> anyhow::Result<String> {
    match token {
        Some(ntoken) => {
            match crate::helpers::token::check(scylla, ntoken).await {
                Ok(data) => Ok(data),
                Err(e) => {
                    if e.to_string() == *"revoked" {
                        Ok("Suspended".to_string())
                    } else if e.to_string() == *"expired" {
                        Ok("Invalid".to_string())
                    } else {
                        Ok(fallback.to_string())
                    }
                }
            }
        }
        _ => Ok(fallback.to_string()),
    }
}

/// Create message error easier
fn err(message: String) -> WithStatus<Json> {
    warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: true,
            message,
        }),
        warp::http::StatusCode::BAD_REQUEST,
    )
}

/// Return an error with rate limit informations
fn rate() -> WithStatus<Json> {
    warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: true,
            message: "Rate limit exceeded".to_string(),
        }),
        warp::http::StatusCode::TOO_MANY_REQUESTS,
    )
}
