use anyhow::Result;
use db::memcache::{MemcacheManager, MemcachePool};
use db::scylla::Scylla;
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

const VALID_SCOPE: [&str; 1] = ["identity"];

/// Route to create an authorization code to obtain an access token.
pub async fn create(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    query: crate::model::query::OAuth,
    token: String,
) -> Result<WithStatus<Json>> {
    let vanity = match crate::helpers::token::get(&scylla, &token).await {
        Ok(vanity) => vanity,
        Err(_) => {
            return Ok(super::err(super::INVALID_TOKEN));
        },
    };

    // Check if scopes are valid.
    let scopes: Vec<&str> = query.scope.split("%20").collect();
    if !scopes.iter().all(|scope| VALID_SCOPE.contains(scope)) {
        return Ok(super::err("Invalid scope"));
    }

    let bot = scylla
        .connection
        .query(
            "SELECT deleted, redirect_url FROM accounts.bots WHERE id = ?",
            vec![&query.client_id],
        )
        .await?
        .rows_typed::<(bool, Vec<String>)>()?
        .collect::<Vec<_>>();

    // Check if bot exists.
    if bot.is_empty() {
        return Ok(super::err(super::INVALID_BOT));
    }

    let (deleted, redirect_uris) = bot[0].clone().unwrap();

    if deleted {
        return Ok(super::err("Bot has been deleted"));
    } else if redirect_uris.iter().any(|x| x == &query.redirect_uri) {
        return Ok(super::err("Invalid redirect_uri"));
    }

    // Create crypto-secure random 31-character authorization token.
    let id = crypto::random_string(31);

    memcached.set(
        &id,
        format!(
            "{}+{}+{}+{}",
            query.client_id, query.redirect_uri, vanity, query.scope
        ),
    )?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: id,
        }),
        warp::http::StatusCode::OK,
    ))
}

/// Get a json web token (JWT) access token from authorization code.
pub async fn get_token(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::OAuth,
) -> Result<WithStatus<Json>> {
    let data = match memcached.get(&body.code)? {
        Some(r) => Vec::from_iter(r.split('+').map(|x| x.to_string())),
        None => vec![],
    };

    // If no code exists, return an error.
    if data.is_empty() {
        return Ok(super::err("Invalid code"));
    }

    let (client_id, redirect_uri, user_id, scope) = match data.as_slice() {
        [client_id, redirect_uri, user_id, scope] => {
            (client_id, redirect_uri, user_id, scope)
        },
        _ => return Ok(super::err(super::INTERNAL_SERVER_ERROR)),
    };

    if &body.client_id != client_id {
        return Ok(super::err(super::INVALID_BOT));
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
        return Ok(super::err(super::INVALID_BOT));
    }

    let (deleted, redirect_uris, client_secret) = bot[0].clone().unwrap();

    if deleted {
        return Ok(super::err("Bot has been deleted"));
    }
    // Also check if redirect_uri is still valid.
    // This can be useful in cases where an intruder has modified the redirection
    // URLs and the developer has become aware of this.
    else if redirect_uris.iter().any(|x| x == &body.redirect_uri)
        && redirect_uris.iter().any(|x| x == redirect_uri)
    {
        return Ok(super::err("Invalid redirect_uri"));
    } else if client_secret != body.client_secret {
        return Ok(super::err("Invalid client_secret"));
    }

    // Deleted used authorization code.
    memcached.delete(body.code)?;

    // Create access token.
    let (expires_in, access_token) = crate::helpers::token::create_jwt(
        user_id.to_string(),
        scope.split_whitespace().map(|x| x.to_string()).collect(),
    )?;

    // To do: `INSERT INTO accounts.oauth ( id, user_id, bot_id, scope, deleted ) VALUES (?, ?, ?, ?, ?)`
    // To do: refresh token.

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::AccessToken {
            access_token,
            expires_in,
            refresh_token: String::default(),
            refresh_token_expires_in: 0,
            scope: scope.to_string(),
        }),
        warp::http::StatusCode::CREATED,
    ))
}
