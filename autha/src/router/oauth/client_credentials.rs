use super::VALID_SCOPE;
use anyhow::Result;
use db::scylla::Scylla;
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

/// Handle creation of `access_token` from client_id and client_secret.
/// Only create an `access_token` for get application data.
/// All scopes are enabled by default. Specifying them will disable those not mentioned.
pub async fn client_credentials(
    scylla: Arc<Scylla>,
    body: crate::model::body::OAuth,
) -> Result<WithStatus<Json>> {
    if body.client_secret.is_none() {
        return Ok(crate::router::err("Invalid body"));
    }

    let client_id = if let Some(client_id) = body.client_id {
        client_id
    } else {
        return Ok(crate::router::err("Invalid body"));
    };

    let scopes: Vec<String> = if let Some(scope) = body.scope {
        scope.split("%20").map(|x| x.to_string()).collect()
    } else {
        VALID_SCOPE.iter().map(|scope| scope.to_string()).collect()
    };

    // Check if specified scopes are valid.
    if !scopes.iter().all(|scope| VALID_SCOPE.contains(&&scope[..])) {
        return Ok(crate::router::err("Invalid scope"));
    }

    let bot = scylla
        .connection
        .query(
            "SELECT deleted, client_secret FROM accounts.bots WHERE id = ?",
            vec![&client_id],
        )
        .await?
        .rows_typed::<(bool, String)>()?
        .collect::<Vec<_>>();

    // Check if bot still exists.
    if bot.is_empty() {
        return Ok(crate::router::err(crate::router::INVALID_BOT));
    }

    let (deleted, client_secret) = bot[0].clone().unwrap();

    if deleted {
        return Ok(crate::router::err("Bot has been deleted"));
    } else if client_secret != body.client_secret.unwrap_or_default() {
        return Ok(crate::router::err("Invalid client_secret"));
    }

    // Create access token.
    let (expires_in, access_token) = crate::helpers::token::create_jwt(
        client_id,
        scopes.iter().map(|scope| scope.to_string()).collect(),
    )?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::AccessToken {
            access_token,
            expires_in,
            refresh_token: String::default(),
            refresh_token_expires_in: 0,
            scope: scopes.join(" "),
            token_type: "Bot".to_string(),
        }),
        warp::http::StatusCode::OK,
    ))
}
