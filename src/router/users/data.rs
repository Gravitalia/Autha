use crate::database::{get_user, scylla::query};
use crate::helpers::crypto::decrypt;
use anyhow::{anyhow, Result};
use scylla::IntoTypedRows;
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

// Define query
const GET_TOKENS: &str = "SELECT ip, date, expire_at, deleted FROM accounts.tokens WHERE user_id = ?;";
const GET_PASSWORD: &str =
    "SELECT password FROM accounts.users WHERE vanity = ?;";

/// This route allows to obtain every data saved by Autha
pub async fn get_data(
    scylla: Arc<scylla::Session>,
    token: String,
    body: crate::model::body::Gdrp,
) -> Result<WithStatus<Json>> {
    let middelware_res =
        crate::router::middleware(Arc::clone(&scylla), Some(token), "Invalid")
            .await
            .unwrap_or_else(|_| "Invalid".to_string());

    let vanity: String =
        if middelware_res != "Invalid" && middelware_res != "Suspended" {
            middelware_res.to_lowercase()
        } else {
            return Ok(warp::reply::with_status(
                warp::reply::json(&crate::model::error::Error {
                    error: true,
                    message: "Invalid token".to_string(),
                }),
                warp::http::StatusCode::UNAUTHORIZED,
            ));
        };

    // Check if security token is valid
    match crate::helpers::request::check_turnstile(body.security_token).await {
        Ok(res) => {
            if !res {
                return Ok(crate::router::err(
                    "Invalid security_token".to_string(),
                ));
            }
        }
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    let query_res =
        query(Arc::clone(&scylla), GET_PASSWORD, vec![vanity.clone()])
            .await?
            .rows
            .unwrap_or_default();

    // Check password
    if !query_res.is_empty()
        && !crate::helpers::crypto::hash_test(
            query_res[0].columns[0]
                .as_ref()
                .ok_or_else(|| anyhow!("No reference"))?
                .as_text()
                .ok_or_else(|| anyhow!("Can't convert to string"))?,
            body.password.as_ref(),
        )
    {
        return Ok(crate::router::err("Invalid password".to_string()));
    }

    // User data
    let user =
        get_user(Arc::clone(&scylla), None, vanity.clone(), vanity.clone())
            .await?
            .1;

    // Connection data
    let mut tokens: Vec<crate::model::user::Token> = vec![];

    if let Some(rows) = query(Arc::clone(&scylla), GET_TOKENS, vec![vanity])
        .await?
        .rows
    {
        for row_data in rows.into_typed::<crate::model::user::Token>() {
            let row_data = row_data?;

            tokens.push(crate::model::user::Token {
                ip: decrypt(Arc::clone(&scylla), row_data.ip).await?,
                date: row_data.date,
                expire_at: row_data.expire_at,
                deleted: row_data.deleted,
            });
        }
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::user::UserData { user, tokens }),
        warp::http::StatusCode::OK,
    ))
}
