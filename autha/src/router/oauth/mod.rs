mod authorization_code;
mod client_credentials;
mod refresh;
pub mod revoke;

use anyhow::Result;
use db::memcache::MemcachePool;
use db::scylla::Scylla;
use std::convert::Infallible;
use std::sync::Arc;
use url::Url;
use warp::{
    http::Uri,
    reply::{Json, Reply, WithStatus},
};

const VALID_SCOPE: [&str; 1] = ["identity"];
const REFRESH_TOKEN_LENGTH: usize = 512;

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
) -> Result<impl Reply, Infallible> {
    match match body.grant_type.as_str() {
        "authorization_code" => {
            authorization_code::authorization_code(scylla, memcached, body)
                .await
        },
        "client_credentials" => {
            client_credentials::client_credentials(scylla, body).await
        },
        "refresh_token" => refresh::refresh_token(scylla, body).await,
        _ => Ok(super::err("Invalid grant_type")),
    } {
        Ok(response) => Ok(response),
        Err(error) => {
            log::error!(
                "Failed to generate access or refresh token: {}",
                error
            );
            Ok(super::err(super::INTERNAL_SERVER_ERROR))
        },
    }
}
