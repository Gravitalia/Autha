use crate::database::{memcached::MemcachePool, scylla::Scylla};
use anyhow::Result;
use warp::reply::{Json, WithStatus};

/// Handle create route and check if everything is valid
pub async fn handle(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Create,
    ip: String,
    token: Option<String>,
) -> Result<WithStatus<Json>> {
    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: "OK".to_string(),
        }),
        warp::http::StatusCode::CREATED,
    ))
}
