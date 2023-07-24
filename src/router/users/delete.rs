use crate::helpers::request::delete_account;
use crate::{database::scylla::query, helpers};
use anyhow::{anyhow, Result};
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

// Define query
const GET_USER_PASSWORD: &str =
    "SELECT password FROM accounts.users WHERE vanity = ?;";
const DELETE_USER: &str =
    "UPDATE accounts.users SET deleted = true, expire_at = ? WHERE vanity = ?;";

/// Delete route for remove account from database
pub async fn delete(
    scylla: Arc<scylla::Session>,
    token: String,
    body: crate::model::body::Gdrp,
) -> Result<WithStatus<Json>> {
    let vanity: String;

    let middelware_res =
        crate::router::middleware(Arc::clone(&scylla), Some(token), "Invalid")
            .await
            .unwrap_or_else(|_| "Invalid".to_string());

    if middelware_res != "Invalid" && middelware_res != "Suspended" {
        vanity = middelware_res.to_lowercase();
    } else {
        return Ok(warp::reply::with_status(
            warp::reply::json(&crate::model::error::Error {
                error: true,
                message: "Invalid token".to_string(),
            }),
            warp::http::StatusCode::UNAUTHORIZED,
        ));
    }

    let res =
        query(Arc::clone(&scylla), GET_USER_PASSWORD, vec![vanity.clone()])
            .await?
            .rows
            .unwrap_or_default();

    if res.is_empty() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&crate::model::error::Error {
                error: true,
                message: "Unknown user".to_string(),
            }),
            warp::http::StatusCode::NOT_FOUND,
        ));
    }

    // Check if security token is valid
    match crate::helpers::request::check_turnstile(body.security_token).await {
        Ok(res) => {
            if !res {
                return Ok(crate::router::err("Invalid user".to_string()));
            }
        }
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    // Check if password matches
    if !crate::helpers::crypto::hash_test(
        &res[0].columns[1]
            .as_ref()
            .ok_or_else(|| anyhow!("No reference"))?
            .as_text()
            .ok_or_else(|| anyhow!("Can't convert to string"))?,
        body.password.as_ref(),
    ) {
        return Ok(crate::router::err("Invalid password".to_string()));
    }

    // Delete also account in others services
    for url in helpers::config_reader::read()
        .services
        .iter()
        .map(|s| s.to_owned())
    {
        let _ = delete_account(url, vanity.clone()).await;
    }

    query(
        scylla,
        DELETE_USER,
        (
            (chrono::Utc::now() + chrono::Duration::days(30)).timestamp(),
            vanity,
        ),
    )
    .await?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: "OK".to_string(),
        }),
        warp::http::StatusCode::OK,
    ))
}
