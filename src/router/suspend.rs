use crate::database::scylla::query;
use anyhow::{Result, Context, anyhow};
use warp::reply::{WithStatus, Json};
use std::sync::Arc;

const UPDATE_USER_DELETED: &str = "UPDATE accounts.users SET deleted = ? WHERE vanity = ?;";
const SELECT_USER_TOKENS_QUERY: &str = "SELECT id FROM accounts.tokens WHERE user_id = ?;";
const UPDATE_TOKEN_QUERY: &str = "UPDATE accounts.tokens SET deleted = true WHERE id = ?;";

/// Suspend a user and block each tokens in database
pub async fn suspend_user(scylla: Arc<scylla::Session>, vanity: String, deleted: bool) -> Result<()> {
    query(Arc::clone(&scylla), UPDATE_USER_DELETED, (
        deleted,
        vanity.clone()
    )).await
        .context("Failed to update user")?;

    if deleted {
        let tokens_res = query(Arc::clone(&scylla), SELECT_USER_TOKENS_QUERY, vec![vanity]).await?.rows.unwrap_or_default();

        for data in tokens_res {
            query(Arc::clone(&scylla), UPDATE_TOKEN_QUERY, vec![
                data.columns[0].as_ref().ok_or_else(|| anyhow!("No reference"))?.as_text().ok_or_else(|| anyhow!("Can't convert to string"))?
            ])
                .await
                .context("Failed to update token")?;
        }
    }

    Ok(())
}

/// Route to suspend a user
pub async fn suspend(scylla: Arc<scylla::Session>, query: crate::model::query::Suspend, token: String) -> Result<WithStatus<Json>> {
    // Check if token is valid
    if token != std::env::var("GLOBAL_AUTH")? {
        return Ok(super::err("Invalid user".to_string()));
    }

    // Suspend user and all active connections
    suspend_user(scylla, query.vanity, query.suspend.unwrap_or_default()).await?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: "OK".to_string(),
        }),
        warp::http::StatusCode::OK,
    ))
}