use crate::{database::cassandra::query};
use warp::reply::{WithStatus, Json};
use anyhow::Result;

pub fn suspend_user(vanity: String) -> Result<()> {
    query("UPDATE accounts.users SET deleted = true WHERE vanity = ?", vec![vanity.clone()])?;

    let res = query("SELECT id FROM accounts.tokens WHERE user_id = ?", vec![vanity])?.get_body()?.as_cols().unwrap().rows_content.clone();
    for data in res {
        query("UPDATE accounts.tokens SET deleted = true WHERE id = ?", vec![std::str::from_utf8(&data[0].clone().into_plain().unwrap()[..])?.to_string()])?;
    }

    Ok(())
}

/// Route to suspend a user
pub fn suspend(vanity: String, token: String) -> Result<WithStatus<Json>> {
    // Check if token is valid
    if token != dotenv::var("GLOBAL_AUTH")? {
        return Ok(super::err("Invalid user".to_string()));
    }

    // Suspend user and all active connections
    suspend_user(vanity)?;

    Ok(warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: false,
            message: "OK".to_string(),
        }
    ),
    warp::http::StatusCode::OK))
}