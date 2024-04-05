use anyhow::Result;
use crypto::{hash::sha::sha256, random_string};
use db::memcache::MemcachePool;
use db::scylla::Scylla;
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

use crate::helpers::queries::CREATE_OAUTH;

const MAX_CODE_CHALLENGE_LENGTH: u8 = 128;
const MIN_CODE_CHALLENGE_LENGTH: u8 = 43;

/// Handle creation of `access_token` from an authorization code.
pub async fn authorization_code(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::OAuth,
) -> Result<WithStatus<Json>> {
    if body.client_id.is_none()
        || body.client_secret.is_none()
        || body.redirect_uri.is_none()
    {
        return Ok(crate::router::err("Invalid body"));
    }

    let code = match body.code {
        Some(code) => code,
        None => return Ok(crate::router::err("Missing code")),
    };

    let data = match memcached.get(&code)? {
        Some(r) => Vec::from_iter(r.split('+').map(|x| x.to_string())),
        None => vec![],
    };

    // If no code exists, return an error.
    if data.is_empty() {
        return Ok(crate::router::err("Invalid code"));
    }

    let (client_id, redirect_uri, user_id, scope, code_challenge) = match data
        .as_slice()
    {
        [client_id, redirect_uri, user_id, scope] => {
            (client_id, redirect_uri, user_id, scope, None)
        },
        [client_id, redirect_uri, user_id, scope, code_challenge] => (
            client_id,
            redirect_uri,
            user_id,
            scope,
            Some(code_challenge),
        ),
        _ => {
            return Ok(crate::router::err(crate::router::INTERNAL_SERVER_ERROR))
        },
    };

    if &body.client_id.unwrap_or_default() != client_id {
        return Ok(crate::router::err(crate::router::INVALID_BOT));
    } else if code_challenge.is_some() && body.code_verifier.is_none() {
        return Ok(crate::router::err("You must use `code_verifier`"));
    }

    if let Some(code_verifier) = body.code_verifier {
        if (code_verifier.len() as u8) < MIN_CODE_CHALLENGE_LENGTH
            || (code_verifier.len() as u8) > MAX_CODE_CHALLENGE_LENGTH
        {
            return Ok(crate::router::err(
                "`code_verifier` must be between 43 and 128 characters long",
            ));
        }

        if let Some(code_challenge) = code_challenge {
            if *code_challenge != sha256(code_verifier.as_bytes()) {
                return Ok(crate::router::err("Invalid `code_verifier`"));
            }
        }
    }

    let bot = scylla
        .connection
        .query(
            "SELECT deleted, redirect_url, client_secret FROM accounts.bots WHERE id = ?",
            vec![client_id],
        )
        .await?
        .rows_typed::<(bool, Vec<String>, String)>()?
        .collect::<Vec<_>>();

    // Check if bot still exists.
    if bot.is_empty() {
        return Ok(crate::router::err(crate::router::INVALID_BOT));
    }

    let (deleted, redirect_uris, client_secret) = bot[0].clone().unwrap();
    let url = body.redirect_uri.unwrap_or_default();

    if deleted {
        return Ok(crate::router::err("Bot has been deleted"));
    }
    // Also check if redirect_uri is still valid.
    // This can be useful in cases where an intruder has modified the redirection
    // URLs and the developer has become aware of this.
    else if redirect_uris.iter().any(|x| x == &url)
        && redirect_uris.iter().any(|x| x == redirect_uri)
    {
        return Ok(crate::router::err("Invalid redirect_uri"));
    } else if client_secret != body.client_secret.unwrap_or_default() {
        return Ok(crate::router::err("Invalid client_secret"));
    }

    // Deleted used authorization code.
    memcached.delete(code)?;

    let scopes: Vec<String> =
        scope.split_whitespace().map(|x| x.to_string()).collect();

    // Create access token.
    let (expires_in, access_token) = crate::helpers::token::create_jwt(
        client_id.to_string(),
        user_id.to_string(),
        scopes.clone(),
    )?;

    // Generate crypto-secure random 512 bytes string.
    let refresh_token = random_string(super::REFRESH_TOKEN_LENGTH);
    if let Some(query) = CREATE_OAUTH.get() {
        scylla
            .connection
            .execute(
                query,
                (&refresh_token, &user_id, &client_id, scopes, false),
            )
            .await?;
    } else {
        log::error!("Prepared queries do not appear to be initialized.");
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::AccessToken {
            access_token,
            expires_in,
            refresh_token,
            refresh_token_expires_in: 5_184_000, // 60 days.
            scope: scope.to_string(),
            token_type: "Bearer".to_string(),
        }),
        warp::http::StatusCode::CREATED,
    ))
}
