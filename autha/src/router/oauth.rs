use anyhow::Result;
use crypto::random_string;
use db::memcache::MemcachePool;
use db::scylla::Scylla;
use std::sync::Arc;
use url::Url;
use warp::{
    http::Uri,
    reply::{Json, Reply, WithStatus},
};

use crate::helpers::queries::CREATE_OAUTH;

const VALID_SCOPE: [&str; 1] = ["identity"];
const MAX_CODE_CHALLENGE_LENGTH: u8 = 128;
const MIN_CODE_CHALLENGE_LENGTH: u8 = 43;

/// This route allows you to create an `authorization code` and then obtain an access token linked to a user.
/// This is an implementation made for a grant type specified on `authorization_code`.
pub async fn authorize(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    query: crate::model::query::OAuth,
    token: String,
) -> Result<warp::http::Response<warp::hyper::Body>, WithStatus<Json>> {
    let vanity = match crate::helpers::token::get(&scylla, &token).await {
        Ok(vanity) => vanity,
        Err(_) => {
            return Err(super::err(super::INVALID_TOKEN));
        },
    };

    // Check if scopes are valid.
    let scopes: Vec<&str> = query.scope.split("%20").collect();
    if !scopes.iter().all(|scope| VALID_SCOPE.contains(scope)) {
        return Err(super::err("Invalid scope"));
    }

    let bot = scylla
        .connection
        .query(
            "SELECT deleted, redirect_url FROM accounts.bots WHERE id = ?",
            vec![&query.client_id],
        )
        .await
        .map_err(|_| super::err(super::INTERNAL_SERVER_ERROR))?
        .rows_typed::<(bool, Vec<String>)>()
        .map_err(|_| super::err(super::INTERNAL_SERVER_ERROR))?
        .collect::<Vec<_>>();

    // Check if bot exists.
    if bot.is_empty() {
        return Err(super::err(super::INVALID_BOT));
    }

    let (deleted, redirect_uris) = bot[0].clone().unwrap();

    if deleted {
        return Err(super::err("Bot has been deleted"));
    } else if redirect_uris.iter().any(|x| x == &query.redirect_uri) {
        return Err(super::err("Invalid redirect_uri"));
    }

    let dectorticed_redirect_url = Url::parse(&query.redirect_uri)
        .map_err(|_| super::err("Invalid redirect_uri"))?;
    let base_redirect = Uri::builder()
        .scheme("https") // Enforce HTTPS.
        .authority(dectorticed_redirect_url.host_str().unwrap_or_default());

    let pkce_code = match (&query.code_challenge_method, &query.code_challenge)
    {
        (Some(method), Some(challenge)) if method == "S256" => Some(challenge),
        (Some(_), None) => {
            return Ok(warp::redirect(
                base_redirect
                .path_and_query(
                    format!("{}?error=invalid_request&error_description=Parameter%20'code_challenge'%20is%20missing.", dectorticed_redirect_url.path())
                )
                .build()
                .map_err(|_| super::err(super::INTERNAL_SERVER_ERROR))?
            ).into_response());
        },
        (Some(_), _) => {
            return Ok(warp::redirect(
                base_redirect
                .path_and_query(
                    format!("{}?error=invalid_request&error_description=Unsupported%20'code_challenge_method'%20parameter.", dectorticed_redirect_url.path())
                )
                .build()
                .map_err(|_| super::err(super::INTERNAL_SERVER_ERROR))?
            ).into_response());
        },
        _ => None,
    };

    // Create crypto-secure random 43-character authorization token.
    let id = crypto::random_string(43);

    if let Some(code_challenge) = pkce_code {
        memcached
            .set(
                &id,
                format!(
                    "{}+{}+{}+{}+{}",
                    query.client_id,
                    query.redirect_uri,
                    vanity,
                    query.scope,
                    code_challenge
                ),
            )
            .map_err(|_| super::err(super::INTERNAL_SERVER_ERROR))?;
    } else {
        memcached
            .set(
                &id,
                format!(
                    "{}+{}+{}+{}",
                    query.client_id, query.redirect_uri, vanity, query.scope
                ),
            )
            .map_err(|_| super::err(super::INTERNAL_SERVER_ERROR))?;
    }

    Ok(warp::redirect(
        base_redirect
            .path_and_query(if let Some(state) = query.state {
                format!(
                    "{}?code={}&state={}",
                    dectorticed_redirect_url.path(),
                    id,
                    state
                )
            } else {
                format!("{}?code={}", dectorticed_redirect_url.path(), id)
            })
            .build()
            .map_err(|_| super::err(super::INTERNAL_SERVER_ERROR))?,
    )
    .into_response())
}

/// Manages the various resources of the OAuth route in order to generate access tokens.
pub async fn grant(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::OAuth,
) -> Result<WithStatus<Json>> {
    match body.grant_type.as_str() {
        "authorization_code" => {
            authorization_code(scylla, memcached, body).await
        },
        "refresh_token" => refresh_token(scylla, body).await,
        _ => Ok(super::err("Invalid grant_type")),
    }
}

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
        return Ok(super::err("Invalid body"));
    }

    let code = match body.code {
        Some(code) => code,
        None => return Ok(super::err("Missing code")),
    };

    let data = match memcached.get(&code)? {
        Some(r) => Vec::from_iter(r.split('+').map(|x| x.to_string())),
        None => vec![],
    };

    // If no code exists, return an error.
    if data.is_empty() {
        return Ok(super::err("Invalid code"));
    }

    let (client_id, redirect_uri, user_id, scope, code_challenge) =
        match data.as_slice() {
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
            _ => return Ok(super::err(super::INTERNAL_SERVER_ERROR)),
        };

    if &body.client_id.unwrap_or_default() != client_id {
        return Ok(super::err(super::INVALID_BOT));
    } else if code_challenge.is_some() && body.code_verifier.is_none() {
        return Ok(super::err("You must use `code_verifier`"));
    }

    if let Some(code_verifier) = body.code_verifier {
        if (code_verifier.len() as u8) < MIN_CODE_CHALLENGE_LENGTH
            || (code_verifier.len() as u8) > MAX_CODE_CHALLENGE_LENGTH
        {
            return Ok(super::err(
                "`code_verifier` must be between 43 and 128 characters long",
            ));
        }

        if let Some(code_challenge) = code_challenge {
            if *code_challenge != crypto::hash::sha256(code_verifier.as_bytes())
            {
                return Ok(super::err("Invalid `code_verifier`"));
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
        return Ok(super::err(super::INVALID_BOT));
    }

    let (deleted, redirect_uris, client_secret) = bot[0].clone().unwrap();
    let url = body.redirect_uri.unwrap_or_default();

    if deleted {
        return Ok(super::err("Bot has been deleted"));
    }
    // Also check if redirect_uri is still valid.
    // This can be useful in cases where an intruder has modified the redirection
    // URLs and the developer has become aware of this.
    else if redirect_uris.iter().any(|x| x == &url)
        && redirect_uris.iter().any(|x| x == redirect_uri)
    {
        return Ok(super::err("Invalid redirect_uri"));
    } else if client_secret != body.client_secret.unwrap_or_default() {
        return Ok(super::err("Invalid client_secret"));
    }

    // Deleted used authorization code.
    memcached.delete(code)?;

    let scopes: Vec<String> =
        scope.split_whitespace().map(|x| x.to_string()).collect();

    // Create access token.
    let (expires_in, access_token) =
        crate::helpers::token::create_jwt(user_id.to_string(), scopes.clone())?;

    // Generate crypto-secure random 512 bytes string.
    let refresh_token = random_string(512);
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

/// Handle creation of `access_token` from a refresh token.
pub async fn refresh_token(
    scylla: Arc<Scylla>,
    body: crate::model::body::OAuth,
) -> Result<WithStatus<Json>> {
    let refresh_token = if let Some(token) = body.refresh_token {
        token
    } else {
        return Ok(super::err("Missing refresh_token"));
    };

    let rows = scylla
        .connection
        .query(
            "SELECT user_id, scope, deleted FROM accounts.oauth WHERE id = ?",
            vec![&refresh_token],
        )
        .await?
        .rows_typed::<(String, Vec<String>, bool)>()?
        .collect::<Vec<_>>();

    let (user_id, scopes, deleted) = rows[0].clone()?;

    if deleted {
        return Ok(super::err("Expired refresh_token"));
    }

    // Create access token.
    let (expires_in, access_token) =
        crate::helpers::token::create_jwt(user_id, scopes.clone())?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::AccessToken {
            access_token,
            expires_in,
            refresh_token,
            refresh_token_expires_in: 0,
            scope: scopes.join(" "),
            token_type: "Bearer".to_string(),
        }),
        warp::http::StatusCode::CREATED,
    ))
}
