pub mod create;

use db::{memcache::MemcachePool, scylla::Scylla};
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

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
pub async fn create_user(
    scylla: Arc<Scylla>,
    body: crate::model::body::Create,
    cf_token: Option<String>,
) -> Result<impl Reply, Rejection> {
    match create::handle(scylla, body, cf_token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}
