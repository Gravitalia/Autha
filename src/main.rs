mod database;
mod helpers;
mod router;
mod model;

#[macro_use] extern crate lazy_static;
use warp::{Filter, reject::Reject, http::StatusCode, Reply, Rejection};
use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, fmt::Debug};
use helpers::ratelimiter::RateLimiter;
use std::sync::{Arc, Mutex};
use std::error::Error;
use memcache::Client;
use scylla::Session;
use regex::Regex;

lazy_static! {
    static ref TOKEN: Regex = Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)").unwrap();
}

// Define errors
#[derive(Debug)]
struct UnknownError;
impl Reject for UnknownError {}

#[derive(Debug)]
struct RateLimitExceeded;
impl Reject for RateLimitExceeded {}

/// This function receives a `Rejection` and tries to return a custom
/// value, otherwise simply passes the rejection along.
async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let code;
    let message: String;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not found".to_string();
    } else if let Some(_) = err.find::<RateLimitExceeded>() {
        message = "Rate limit exceeded".to_string();
        code = StatusCode::TOO_MANY_REQUESTS;
    } else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        message = match e.source() {
            Some(cause) => {
                cause.to_string()
            }
            None => "Invalid body".to_string(),
        };
        code = StatusCode::BAD_REQUEST;
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method not allowed".to_string();
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal server error".to_string();
    }

    Ok(warp::reply::with_status(warp::reply::json(&model::error::Error {
        error: true,
        message,
    }), code))
}

/// Handle requests and verify limits per IP
async fn rate_limit(rate_limiter: Arc<Mutex<RateLimiter>>, ip: String) -> Result<(), Rejection> {
    let mut rate_limiter = rate_limiter.lock().unwrap();
    if rate_limiter.check_rate(&ip) {
        Ok(())
    } else {
        // Reject the request if the rate limit is exceeded
        Err(warp::reject::custom(RateLimitExceeded))
    }
}

#[tokio::main]
async fn main() {
    println!("Starting server...");

    // Starts database
    let scylla = Arc::new(database::scylla::init().await.unwrap());
    let memcached = database::mem::init().unwrap();

    // Create tables
    database::scylla::create_tables(Arc::clone(&scylla)).await;

    // Delete all old accounts
    helpers::remove_deleted_account(Arc::clone(&scylla)).await;

    // Add middleware to rate-limit
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

    // Create routes
    let routes = warp::path("create")
                    .and(warp::post())
                    .and(warp::any().map(move || Arc::clone(&scylla)))
                    .and(warp::any().map(move || memcached.clone()))
                    .and(warp::any().map(move || rate_limiter.clone()))
                    .and(warp::body::json())
                    .and(warp::header("cf-turnstile-token"))
                    .and(warp::header::optional::<String>("X-Forwarded-For"))
                    .and(warp::addr::remote())
                    .and_then(|scylla: std::sync::Arc<Session>, memcached: Client, limiter: Arc<Mutex<RateLimiter>>, body: model::body::Create, cf_token: String, forwarded: Option<String>, ip: Option<SocketAddr>| async move {
                        let ip = forwarded.unwrap_or_else(|| ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip().to_string());

                        match rate_limit(limiter, ip.clone()).await {
                            Ok(_) => {
                                match router::create::create(scylla, memcached, body, ip, cf_token).await {
                                    Ok(r) => {
                                        Ok(r)
                                    },
                                    Err(_) => {
                                        Err(warp::reject::custom(UnknownError))
                                    }
                                }
                            },
                            Err(e) => {
                                Err(e)
                            }
                        }
                    })
                    .recover(handle_rejection);

    let port = std::env::var("PORT").unwrap_or_else(|_| "1111".to_string()).parse::<u16>().unwrap();
    println!("Server started on port {}", port);

    warp::serve(
        warp::any().and(warp::options()).map(|| "OK")
        .or(routes)
    )
    .run((
        [0, 0, 0, 0],
        port
    ))
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex() {
        assert!(TOKEN.is_match("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    }
}