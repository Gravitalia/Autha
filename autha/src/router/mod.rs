pub mod create;
pub mod login;
pub mod users;

use db::{memcache::MemcachePool, scylla::Scylla};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

// Error constants.
const ERROR_RATE_LIMITED: &str = "You are being rate limited.";
const INTERNAL_SERVER_ERROR: &str = "Internal server error";
const INVALID_TURNSTILE: &str = "Invalid turnstile token";
const INVALID_EMAIL: &str = "Invalid email";
const INVALID_PASSWORD: &str = "Invalid password";
const MISSING_AUTHORIZATION_HEADER: &str = "Missing authorization header";
const INVALID_TOKEN: &str = "Invalid token";

/// Define errors
#[derive(Debug)]
struct UnknownError;
impl warp::reject::Reject for UnknownError {}

/// Create a Warp response for errors messages.
/// Should be used in routes.
fn err<T: ToString>(message: T) -> warp::reply::WithStatus<warp::reply::Json> {
    warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
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
) -> impl Filter<Extract = (MemcachePool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db_pool.clone())
}

/// Also creates a Warp filter to inject Scylla into Warp routes.
/// The atomic Scylla session is cloned and returned as an outcome of this filter.
pub fn with_scylla(
    db: Arc<Scylla>,
) -> impl Filter<Extract = (Arc<Scylla>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || Arc::clone(&db))
}

/// Handler of route to create a user.
#[inline]
pub async fn create_user(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Create,
    cf_token: Option<String>,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    match create::handle(
        scylla,
        memcached,
        body,
        cf_token,
        forwarded.unwrap_or_else(|| {
            ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80))
                .ip()
                .to_string()
        }),
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Handler of route to login a user.
#[inline]
pub async fn login_user(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Login,
    cf_token: Option<String>,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    match login::handle(
        scylla,
        memcached,
        body,
        cf_token,
        forwarded.unwrap_or_else(|| {
            ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80))
                .ip()
                .to_string()
        }),
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Handler of route to get a user.
#[inline]
pub async fn get_user(
    vanity: String,
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    token: Option<String>,
) -> Result<impl Reply, Rejection> {
    match users::get(
        scylla,
        memcached,
        vanity,
        token,
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}
