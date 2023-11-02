pub mod create;

use db::{memcache::MemcachePool, scylla::Scylla};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// Define errors
#[derive(Debug)]
struct UnknownError;
impl warp::reject::Reject for UnknownError {}

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

pub async fn create_user(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Create,
    cf_token: Option<String>,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    let ip = forwarded.unwrap_or_else(|| {
        ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80))
            .ip()
            .to_string()
    });

    match create::handle(scylla, memcached, body, ip, cf_token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}
