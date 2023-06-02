use crate::database::cassandra::query;
use warp::reply::{WithStatus, Json};
use anyhow::{Result, Context};

const SELECT_USER_TOKENS_QUERY: &str = "SELECT id FROM accounts.tokens WHERE user_id = ?";
const UPDATE_TOKEN_QUERY: &str = "UPDATE accounts.tokens SET deleted = true WHERE id = ?";

/// Suspend a user and block each tokens in database
pub fn suspend_user(vanity: String, deleted: bool) -> Result<()> {
    query(format!("UPDATE accounts.users SET deleted = {} WHERE vanity = ?", deleted), vec![vanity.clone()])
        .context("Failed to update user")?;

    if deleted {
        let tokens_res = query(SELECT_USER_TOKENS_QUERY, vec![vanity])
            .context("Failed to select user tokens")?
            .get_body()
            .context("Failed to get response body")?
            .as_cols()
            .unwrap()
            .rows_content
            .clone();

        for data in tokens_res {
            let token_id = std::str::from_utf8(&data[0].clone().into_plain().unwrap()[..])
                .context("Failed to convert token ID to string")?
                .to_string();

            query(UPDATE_TOKEN_QUERY, vec![token_id])
                .context("Failed to update token")?;
        }
    }

    Ok(())
}

/// Route to suspend a user
pub fn suspend(query: crate::model::query::Suspend, token: String) -> Result<WithStatus<Json>> {
    // Check if token is valid
    if token != dotenv::var("GLOBAL_AUTH")? {
        return Ok(super::err("Invalid user".to_string()));
    }

    // Suspend user and all active connections
    suspend_user(query.vanity, query.suspend.unwrap_or_default())?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: "OK".to_string(),
        }),
        warp::http::StatusCode::OK,
    ))
}
