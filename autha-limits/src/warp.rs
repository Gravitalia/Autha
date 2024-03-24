use crate::RateLimiter;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use warp::{Filter, Rejection};

/// Rate limited error.
#[derive(Debug)]
pub struct RateLimited;

impl warp::reject::Reject for RateLimited {}

/// Middleware to limit request per window time.
pub fn rate_limiter(
    limiter: Arc<RateLimiter>,
) -> impl Filter<Extract = ((),), Error = Rejection> + Clone {
    warp::any()
        .map(move || Arc::clone(&limiter))
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::addr::remote())
        .and_then(
            |limiter: Arc<RateLimiter>,
             authorization: Option<String>,
             ip: Option<SocketAddr>| async move {
                limiter
                    .check(authorization.unwrap_or_else(|| {
                        ip.unwrap_or_else(|| {
                            SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                0,
                            )
                        })
                        .ip()
                        .to_string()
                    }))
                    .then(|| Ok(()))
                    .unwrap_or_else(|| Err(warp::reject::custom(RateLimited)))
            },
        )
}
