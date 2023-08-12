use crate::database::mem::{del, get};
use crate::{database::scylla::query, helpers};
use anyhow::Result;
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

// Define query
const REINTEGRATE_ACCOUNT: &str = "UPDATE accounts.users SET deleted = false, expire_at = null WHERE vanity = ?";

/// Handle a route to restore a deleted account based on a token
/// generated via the login route
pub async fn recuperate_account(
    scylla: Arc<scylla::Session>,
    code: String,
    token: String,
) -> Result<WithStatus<Json>> {
    // Get user vanity
    let vanity = match get(code.clone())? {
        Some(v) => v,
        None => {
            return Ok(crate::router::err("Invalid code header".to_string()));
        }
    };

    // Check if provided security header is ok
    match helpers::request::check_turnstile(token).await {
        Ok(res) => {
            if !res {
                return Ok(crate::router::err("Invalid user".to_string()));
            }
        }
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    // Delete code
    del(code)?;

    // Restore account
    query(scylla, REINTEGRATE_ACCOUNT, vec![vanity.clone()]).await?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: "Account reintegrated".to_string(),
        }),
        warp::http::StatusCode::OK,
    ))
}
