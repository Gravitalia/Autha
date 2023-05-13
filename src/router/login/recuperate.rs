use crate::{helpers, database::cassandra::query};
use warp::reply::{WithStatus, Json};
use crate::database::mem::{get, del};
use anyhow::Result;

/// Handle a route to restore a deleted account based on a token
/// generated via the login route
pub async fn recuperate_account(code: String, token: String) -> Result<WithStatus<Json>> {
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
                return Ok(crate::router::err("Invalid Cloudflare Turnstile Token".to_string()));
            }
        },
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    // Delete code
    del(code)?;

    // Restore account
    query("UPDATE accounts.users SET deleted = false, expire_at = null WHERE vanity = ?", vec![vanity.clone()])?;

    Ok(warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: false,
            message: "Account reintegrated".to_string(),
        }
    ),
    warp::http::StatusCode::OK))
}
