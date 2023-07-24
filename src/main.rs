mod database;
mod helpers;
mod model;
mod router;

#[macro_use]
extern crate lazy_static;
use helpers::ratelimiter::RateLimiter;
use memcache::Client;
use scylla::Session;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use warp::{http::StatusCode, Filter, Rejection, Reply};

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
async fn rate_limit(
    rate_limiter: Arc<Mutex<RateLimiter>>,
    ip: String,
) -> Result<(), Rejection> {
    let mut rate_limiter = rate_limiter.lock().unwrap();
    if rate_limiter.check_rate(&ip) {
        Ok(())
    } else {
        // Reject the request if the rate limit is exceeded
        Err(warp::reject::custom(RateLimitExceeded))
    }
}

/// Create a new user
async fn create_user(
    scylla: Arc<Session>,
    memcached: Arc<Client>,
    body: model::body::Create,
    cf_token: String,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    let ip = forwarded.unwrap_or_else(|| {
        ip.unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)
        })
        .ip()
        .to_string()
    });

    match router::create::create(scylla, memcached, body, ip, cf_token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Login to an account
async fn login(
    scylla: Arc<Session>,
    memcached: Arc<Client>,
    body: model::body::Login,
    cf_token: String,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    let ip = forwarded.unwrap_or_else(|| {
        ip.unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)
        })
        .ip()
        .to_string()
    });

    match router::login::main::login(scylla, memcached, body, ip, cf_token)
        .await
    {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Route to recuperate a deleted account after 30 days maximum
async fn recuperate_account(
    scylla: Arc<Session>,
    memcached: Arc<Client>,
    code: String,
    cf_token: String,
) -> Result<impl Reply, Rejection> {
    match router::login::recuperate::recuperate_account(
        scylla, memcached, code, cf_token,
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Get user by ID
async fn get_user(
    id: String,
    scylla: Arc<Session>,
    memcached: Arc<Client>,
    limiter: Arc<Mutex<RateLimiter>>,
    token: Option<String>,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    let ip = forwarded.unwrap_or_else(|| {
        ip.unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)
        })
        .ip()
        .to_string()
    });

    match rate_limit(limiter, ip.clone()).await {
        Ok(_) => {
            Ok(router::users::get::get(scylla, memcached, id, token).await)
        }
        Err(e) => Err(e),
    }
}

/// Suspend user from all services
async fn suspend_user(
    scylla: Arc<Session>,
    query: model::query::Suspend,
    token: String,
) -> Result<impl Reply, Rejection> {
    match router::suspend::suspend(scylla, query, token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Returns 5-minute code to get JWT
async fn post_oauth(
    scylla: Arc<Session>,
    memcached: Arc<Client>,
    body: model::body::OAuth,
    token: String,
) -> Result<impl Reply, Rejection> {
    match router::oauth::post(scylla, memcached, body, token).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Get JWT code via the 5-minute code
async fn get_oauth(
    scylla: Arc<Session>,
    memcached: Arc<Client>,
    body: model::body::GetOAuth,
) -> Result<impl Reply, Rejection> {
    match router::oauth::get_oauth_code(scylla, memcached, body).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// Get JWT code via the 5-minute code
async fn delete_user(
    scylla: Arc<Session>,
    body: model::body::Gdrp,
    token: String
) -> Result<impl Reply, Rejection> {
    match router::users::delete::delete(scylla, token, body).await {
        Ok(r) => Ok(r),
        Err(_) => Err(warp::reject::custom(UnknownError)),
    }
}

/// This function receives a `Rejection` and tries to return a custom
/// value, otherwise simply passes the rejection along.
async fn handle_rejection(
    err: Rejection,
) -> Result<impl Reply, std::convert::Infallible> {
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
    } else if let Some(e) =
        err.find::<warp::filters::body::BodyDeserializeError>()
    {
        message = match e.source() {
            Some(cause) => cause.to_string(),
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

    Ok(warp::reply::with_status(
        warp::reply::json(&model::error::Error {
            error: true,
            message,
        }),
        code,
    ))
}

#[tokio::main]
async fn main() {
    println!("Starting server...");

    // Starts database
    let scylla = Arc::new(database::scylla::init().await.unwrap());
    let memcached = Arc::new(database::mem::init().unwrap());

    let login_scylla = Arc::clone(&scylla);
    let login_mem = Arc::clone(&memcached);

    let recuperate_scylla = Arc::clone(&scylla);
    let recuperate_mem = Arc::clone(&memcached);

    let get_scylla = Arc::clone(&scylla);
    let get_mem = Arc::clone(&memcached);

    let suspend_scylla = Arc::clone(&scylla);

    let get_code_scylla = Arc::clone(&scylla);
    let get_code_mem = Arc::clone(&memcached);

    let get_jwt_scylla = Arc::clone(&scylla);
    let get_jwt_mem = Arc::clone(&memcached);

    let delete_scylla = Arc::clone(&scylla);

    // Create tables
    database::scylla::create_tables(Arc::clone(&scylla)).await;

    // Delete all old accounts
    helpers::remove_deleted_account(Arc::clone(&scylla)).await;

    // Add middleware to rate-limit
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

    let create_route = warp::path("create")
        .and(warp::post())
        .and(warp::any().map(move || Arc::clone(&scylla)))
        .and(warp::any().map(move || Arc::clone(&memcached)))
        .and(warp::body::json())
        .and(warp::header("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(create_user);

    let login_route = warp::path("login")
        .and(warp::post())
        .and(warp::any().map(move || Arc::clone(&login_scylla)))
        .and(warp::any().map(move || Arc::clone(&login_mem)))
        .and(warp::body::json())
        .and(warp::header("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(login);

    let recuperate_account_route = warp::path("login")
        .and(warp::path("recuperate"))
        .and(warp::get())
        .and(warp::any().map(move || Arc::clone(&recuperate_scylla)))
        .and(warp::any().map(move || Arc::clone(&recuperate_mem)))
        .and(warp::header("code"))
        .and(warp::header("cf-turnstile-token"))
        .and_then(recuperate_account);

    let get_user_route = warp::path!("users" / String)
        .and(warp::get())
        .and(warp::any().map(move || Arc::clone(&get_scylla)))
        .and(warp::any().map(move || Arc::clone(&get_mem)))
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

    let oauth_code = warp::path("oauth2")
        .and(warp::post())
        .and(warp::any().map(move || Arc::clone(&get_code_scylla)))
        .and(warp::any().map(move || Arc::clone(&get_code_mem)))
        .and(warp::body::json())
        .and(warp::header("authorization"))
        .and_then(post_oauth);

    let get_jwt_code = warp::path("oauth2")
        .and(warp::path("token"))
        .and(warp::post())
        .and(warp::any().map(move || Arc::clone(&get_jwt_scylla)))
        .and(warp::any().map(move || Arc::clone(&get_jwt_mem)))
        .and(warp::body::json())
        .and_then(get_oauth);

    let delete_user = warp::path("users")
        .and(warp::path("@me"))
        .and(warp::delete())
        .and(warp::any().map(move || Arc::clone(&delete_scylla)))
        .and(warp::body::json())
        .and(warp::header("authorization"))
        .and_then(delete_user);

    let routes = create_route
        .or(login_route)
        .or(recuperate_account_route)
        .or(get_user_route)
        .or(suspend_user_route)
        .or(oauth_code)
        .or(get_jwt_code)
        .or(delete_user)
        .recover(handle_rejection);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "1111".to_string())
        .parse::<u16>()
        .unwrap();
    println!("Server started on port {}", port);

    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
