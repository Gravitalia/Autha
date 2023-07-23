mod database;
mod helpers;
mod router;
mod model;

#[macro_use]
extern crate lazy_static;
use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, fmt::Debug};
use warp::{Filter, http::StatusCode, Reply, Rejection};
use helpers::ratelimiter::RateLimiter;
use std::sync::{Arc, Mutex};
use std::error::Error;
use memcache::Client;
use scylla::Session;

// Define errors
#[derive(Debug)]
struct UnknownError;
impl warp::reject::Reject for UnknownError {}

#[derive(Debug)]
struct RateLimitExceeded;
impl warp::reject::Reject for RateLimitExceeded {}

#[derive(Debug)]
struct InvalidAuthorization;
impl warp::reject::Reject for InvalidAuthorization {}

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

/// Create a new user
async fn create_user(scylla: Arc<Session>, memcached: Client, body: model::body::Create, cf_token: String, forwarded: Option<String>, ip: Option<SocketAddr>) -> Result<impl Reply, Rejection> {
    let ip = forwarded.unwrap_or_else(|| ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip().to_string());

    match router::create::create(scylla, memcached, body, ip, cf_token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Login to an account
async fn login(scylla: Arc<Session>, memcached: Client, body: model::body::Login, cf_token: String, forwarded: Option<String>, ip: Option<SocketAddr>) -> Result<impl Reply, Rejection> {
    let ip = forwarded.unwrap_or_else(|| ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip().to_string());

    match router::login::main::login(scylla, memcached, body, ip, cf_token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Get user by ID
async fn get_user(id: String, scylla: Arc<Session>, memcached: Client, limiter: Arc<Mutex<RateLimiter>>, token: Option<String>, forwarded: Option<String>, ip: Option<SocketAddr>) -> Result<impl Reply, Rejection> {
    let ip = forwarded.unwrap_or_else(|| ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip().to_string());

    match rate_limit(limiter, ip.clone()).await {
        Ok(_) => Ok(router::users::get::get(scylla, memcached, id, token).await),
        Err(e) => Err(e),
    }
}

/// Suspend user from all services
async fn suspend_user(scylla: Arc<Session>, query: model::query::Suspend, token: String) -> Result<impl Reply, Rejection> {
    match router::suspend::suspend(scylla, query, token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// This function receives a `Rejection` and tries to return a custom
/// value, otherwise simply passes the rejection along.
async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let code;
    let message: String;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not found".to_string();
    } else if err.find::<RateLimitExceeded>().is_some() {
        message = "Rate limit exceeded".to_string();
        code = StatusCode::TOO_MANY_REQUESTS;
    } else if err.find::<InvalidAuthorization>().is_some() {
        message = "Invalid token".to_string();
        code = StatusCode::UNAUTHORIZED;
    }  else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
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

#[tokio::main]
async fn main() {
    println!("Starting server...");
    dotenv::dotenv().ok();

    // Starts database
    let scylla = Arc::new(database::scylla::init().await.unwrap());
    let memcached = database::mem::init().unwrap();

    let login_scylla = Arc::clone(&scylla);
    let login_mem = memcached.clone();

    let get_scylla = Arc::clone(&scylla);
    let get_mem = memcached.clone();

    let suspend_scylla = Arc::clone(&scylla);

    // Create tables
    database::scylla::create_tables(Arc::clone(&scylla)).await;

    // Delete all old accounts
    helpers::remove_deleted_account(Arc::clone(&scylla)).await;

    // Add middleware to rate-limit
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

    let create_route = warp::path("create")
        .and(warp::post())
        .and(warp::any().map(move || Arc::clone(&scylla)))
        .and(warp::any().map(move || memcached.clone()))
        .and(warp::body::json())
        .and(warp::header("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(create_user);

    let login_route = warp::path("login")
        .and(warp::post())
        .and(warp::any().map(move || Arc::clone(&login_scylla)))
        .and(warp::any().map(move || login_mem.clone()))
        .and(warp::body::json())
        .and(warp::header("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(login);

    let get_user_route = warp::path!("users" / String)
        .and(warp::get())
        .and(warp::any().map(move || Arc::clone(&get_scylla)))
        .and(warp::any().map(move || get_mem.clone()))
        .and(warp::any().map(move || rate_limiter.clone()))
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(get_user);

    let suspend_user_route = warp::path("account")
        .and(warp::path("suspend"))
        .and(warp::post())
        .and(warp::any().map(move || Arc::clone(&suspend_scylla)))
        .and(warp::query::<model::query::Suspend>())
        .and(warp::header("authorization"))
        .and_then(suspend_user);

    let routes = create_route
        .or(login_route)
        .or(get_user_route)
        .or(suspend_user_route)
        .recover(handle_rejection);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "1111".to_string())
        .parse::<u16>()
        .unwrap();
    println!("Server started on port {}", port);

    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
