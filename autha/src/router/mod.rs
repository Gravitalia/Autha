pub mod create;
pub mod login;
pub mod oauth;
pub mod users;

use crate::model::{error::Error, user::Token};
use anyhow::{anyhow, Result};
use db::{memcache::MemcachePool, scylla::Scylla};
use std::{convert::Infallible, sync::Arc};
use warp::{
    http::StatusCode, reject::Reject, reply::Response, Filter, Rejection, Reply,
};

// Error constants.
const ERROR_RATE_LIMITED: &str = "You are being rate limited.";
const INTERNAL_SERVER_ERROR: &str = "Internal server error";
const INVALID_TURNSTILE: &str = "Invalid turnstile token";
const INVALID_EMAIL: &str = "Invalid email";
const INVALID_PASSWORD: &str = "Invalid password";
const MISSING_AUTHORIZATION_HEADER: &str = "Missing authorization header";
const INVALID_TOKEN: &str = "Invalid token";
const INVALID_USERNAME: &str = "Invalid username";
const INVALID_BIRTHDATE: &str = "Too young";
const INVALID_PHONE: &str = "Invalid phone";
const INVALID_BOT: &str = "Invalid client_id";

const DEFAULT_AES_KEY: &str =
    "4D6a514749614D6c74595a50756956446e5673424142524c4f4451736c515233";

/// Define errors
#[derive(Debug)]
#[allow(dead_code)]
pub enum Errors {
    /// An error with absolutely no details.
    Unspecified,
    /// Requester exceed limits of the route.
    ExceedRateLimit,
}
impl Reject for Errors {}

// This function receives a `Rejection` and tries to return a custom
// value, otherwise simply passes the rejection along.
pub async fn handle_rejection(
    err: Rejection,
) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND";
    } else if let Some(autha_error) = err.find::<Errors>() {
        match autha_error {
            Errors::Unspecified => {
                code = StatusCode::METHOD_NOT_ALLOWED;
                message = "Method not allowed";
            },
            Errors::ExceedRateLimit => {
                code = StatusCode::TOO_MANY_REQUESTS;
                message = ERROR_RATE_LIMITED;
            },
        }
    } else if err.find::<autha_limits::warp::RateLimited>().is_some() {
        code = StatusCode::TOO_MANY_REQUESTS;
        message = ERROR_RATE_LIMITED;
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method not allowed";
    } else if err.find::<warp::reject::PayloadTooLarge>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Content is too large.";
    } else {
        log::error!("{:?}", err);

        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = INTERNAL_SERVER_ERROR;
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&Error {
            error: true,
            message: message.into(),
        }),
        code,
    ))
}

/// Gets the user's vanity from the supplied token.
#[inline(always)]
async fn vanity_from_token(scylla: &Arc<Scylla>, token: &str) -> Result<Token> {
    if token.starts_with("Bearer ") {
        let claims =
            crate::helpers::token::get_jwt(&token.replace("Bearer ", ""))
                .map_err(|error| {
                    anyhow!(format!("invalid token: {}", error))
                })?;

        Ok(Token {
            token: token.to_string(),
            vanity: claims.sub.clone(),
            is_bot: claims.client_id == claims.sub, // this means it has been created with client_credidentials.
            scopes: Some(claims.scope),
        })
    } else if token.starts_with("Bot ") {
        Err(anyhow!("bots are not supported"))
    } else {
        let vanity = crate::helpers::token::get(scylla, token)
            .await
            .map_err(|_| anyhow!("invalid token"))?;

        Ok(Token {
            token: token.to_string(),
            vanity,
            is_bot: false,
            scopes: None,
        })
    }
}

/// Create a Warp response for errors messages.
/// Should be used in routes.
fn err<T: ToString>(message: T) -> warp::reply::WithStatus<warp::reply::Json> {
    warp::reply::with_status(
        warp::reply::json(&Error {
            error: true,
            message: message.to_string(),
        }),
        warp::http::StatusCode::BAD_REQUEST,
    )
}

/// Creates a Warp filter that extracts a reference to the provided MemPool.
/// This filter is used to inject a reference to the MemPool (Memcached database pool) into Warp routes.
/// The MemPool is cloned and returned as an outcome of this filter.
pub fn with_memcached(
    db_pool: MemcachePool,
) -> impl Filter<Extract = (MemcachePool,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || db_pool.clone())
}

/// Also creates a Warp filter to inject Scylla into Warp routes.
/// The atomic Scylla session is cloned and returned as an outcome of this filter.
pub fn with_scylla(
    db: Arc<Scylla>,
) -> impl Filter<Extract = (Arc<Scylla>,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || Arc::clone(&db))
}

/// Creates a Warp filter to inject the broker into Warp routes.
pub fn with_broker(
    broker: Arc<db::broker::Broker>,
) -> impl Filter<
    Extract = (Arc<db::broker::Broker>,),
    Error = std::convert::Infallible,
> + Clone {
    warp::any().map(move || Arc::clone(&broker))
}

/// Creates a Warp filter increment Prometheus metrics counters.
pub fn with_metric(
) -> impl Filter<Extract = (), Error = std::convert::Infallible> + Clone {
    warp::any()
        .map(|| {
            #[cfg(feature = "telemetry")]
            crate::telemetry::metrics::HTTP_REQUESTS.inc();
        })
        .untuple_one()
}

/// Handler of route to create an authorization token.
#[inline(always)]
pub async fn create_token(
    _: (),
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    token: String,
    query: crate::model::query::OAuth,
) -> Result<Response, Rejection> {
    match oauth::authorize(scylla, memcached, query, token).await {
        Ok(r) => {
            let res = r.into_response();

            Ok(res)
        },
        Err(error) => Ok(error.into_response()),
    }
}
