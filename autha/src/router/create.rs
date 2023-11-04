use anyhow::Result;
use crypto::{hash::sha256, random_string};
use db::{
    memcache::{MemcacheManager, MemcachePool},
    scylla::Scylla,
};
use regex::Regex;
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

/// Handle create route and check if everything is valid.
pub async fn handle(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Create,
    ip: String,
    token: Option<String>,
) -> Result<WithStatus<Json>> {
    // Use tokio task if async do not work.
    // Email verification via regex.
    if !EMAIL.is_match(&body.email) {
        return Ok(super::err("Invalid email"));
    }
    // Check password length and its reliability.
    if body.password.len() < 8 && !PASSWORD.is_match(&body.password) {
        return Ok(super::err("Invalid password"));
    }
    // Vanity verification.
    if !VANITY.is_match(&body.vanity) || body.vanity.chars().all(|c| c.is_ascii_digit()) {
        return Ok(super::err("Invalid vanity"));
    }
    // Username length check.
    if body.username.len() > 25 {
        return Ok(super::err("Invalid username"));
    }

    // Hash IP.
    let hashed_ip = sha256(ip.as_bytes()).unwrap_or_default();
    if hashed_ip.is_empty() {
        log::warn!(
            "The IP could not be hashed. This can result in the uncontrolled creation of accounts."
        );
    }

    // Check if user have already created account 5 minutes ago.
    let rate_limit = match memcached.get(format!("account_create_{}", hashed_ip))? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 1 {
        return Ok(warp::reply::with_status(
            warp::reply::json(&crate::model::error::Error {
                error: true,
                message: super::ERROR_RATE_LIMITED.into(),
            }),
            warp::http::StatusCode::TOO_MANY_REQUESTS,
        ));
    }

    // Set to one to the global rate limit.
    // One because it can only create ONE account each five minutes.
    memcached.set(
        format!("account_create_{}", hashed_ip),
        1,
    )?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: "OK".to_string(),
        }),
        warp::http::StatusCode::CREATED,
    ))
}
