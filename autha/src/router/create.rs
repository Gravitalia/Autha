use anyhow::Result;
use crypto::{hash::sha256, random_string};
use db::{memcache::MemcachePool, scylla::Scylla};
use regex::Regex;
use tokio::task;
use warp::reply::{Json, WithStatus};

lazy_static! {
    pub static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    pub static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    pub static ref VANITY: Regex = Regex::new(r"[A-z|0-9|_]{3,16}$").unwrap();
    pub static ref PHONE: Regex = Regex::new(
        r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$"
    )
    .unwrap();
    pub static ref BIRTH: Regex =
        Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

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
