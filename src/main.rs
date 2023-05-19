mod model;
mod router;
mod helpers;
mod database;

#[macro_use] extern crate lazy_static;
use warp::{Filter, reject::Reject, http::StatusCode, Reply, Rejection};
use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, fmt::Debug};
use regex::Regex;
use std::error::Error;

lazy_static! {
    static ref TOKEN: Regex = Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
}

#[derive(Debug)]
struct UnknownError;
impl Reject for UnknownError {}

// This function receives a `Rejection` and tries to return a custom
// value, otherwise simply passes the rejection along.
async fn handle_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let code;
    let message: String;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not found".to_string();
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

/// Check if a token is valid and if have a real user behind (not suspended)
fn middleware(token: Option<String>, fallback: &str) -> anyhow::Result<String> {
    match &token {
        Some(ntoken) if fallback == "@me" => {
            if let Ok(data) = helpers::jwt::get_jwt(ntoken.to_string()) {
                if let Ok(user) = database::cassandra::query("SELECT deleted FROM accounts.users WHERE vanity = ?", vec![data.claims.sub.clone()]) {
                    if let Some(row) = user.get_body()?.as_cols().unwrap().rows_content.get(0) {
                        if row.get(0).unwrap().clone().into_plain().unwrap()[..] != [0] {
                            return Ok("Suspended".to_string());
                        } else {
                            return Ok(data.claims.sub);
                        }
                    }
                }
                return Ok(data.claims.sub);
            }
            Ok("Invalid".to_string())
        }
        None if fallback == "@me" => Ok("Invalid".to_string()),
        _ => Ok(fallback.to_string()),
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    println!("Starting server...");

    database::cassandra::init();
    database::cassandra::create_tables();
    let _ = database::mem::init();
    helpers::remove_deleted_account().await;
    
    let routes = warp::path("create").and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and(warp::header::optional::<String>("X-Forwarded-For")).and(warp::addr::remote()).and_then(|body: model::body::Create, cf_token: String, forwarded: Option<String>, ip: Option<SocketAddr>| async move {
        match router::create::create(body, forwarded.unwrap_or_else(|| ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip().to_string()), cf_token).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    })
    .or(warp::path("login").and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and(warp::header::optional::<String>("X-Forwarded-For")).and(warp::addr::remote()).and_then(|body: model::body::Login, cf_token: String, forwarded: Option<String>, ip: Option<SocketAddr>| async move {
        match router::login::main::login(body, forwarded.unwrap_or_else(|| ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip().to_string()), cf_token).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    }))
    .or(warp::path!("users" / String).and(warp::get()).and(warp::header::optional::<String>("authorization")).and_then(|id: String, token: Option<String>| async move {
        if id == "@me" && token.is_some() && TOKEN.is_match(&token.clone().unwrap_or_default()) {
            let oauth = match database::cassandra::query("SELECT user_id FROM accounts.oauth WHERE id = ?", vec![token.unwrap()]) {
                Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
                Err(_) => {
                    return Err(warp::reject::custom(UnknownError));
                }
            };

            if oauth.is_empty() {
                Err(warp::reject::custom(UnknownError))
            } else {
                Ok(router::users::get(std::str::from_utf8(&oauth[0][0].clone().into_plain().unwrap()[..]).unwrap().to_string(), "".to_string()))
            }
        } else {
            let middelware_res = middleware(token, &"fallback").unwrap_or_else(|_| "Invalid".to_string());
            if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
                Ok(router::users::get(if middelware_res == "fallback" { id } else { middelware_res.to_lowercase() }, middelware_res.to_lowercase()))
            } else if middelware_res == *"Suspended" {
                Ok(warp::reply::with_status(warp::reply::json(
                    &model::error::Error{
                        error: true,
                        message: "Account suspended".to_string(),
                    }
                ),
                warp::http::StatusCode::FORBIDDEN))
            } else {
                Err(warp::reject::custom(UnknownError))
            }
        }
    }))
    .or(warp::path("users").and(warp::path("@me")).and(warp::patch()).and(warp::body::json()).and(warp::header::<String>("authorization")).and_then(|body: model::body::UserPatch, token: String| async {
        let middelware_res: String = middleware(Some(token), "@me").unwrap_or_else(|_| "Invalid".to_string());
        if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
            match router::users::patch(middelware_res.to_lowercase(), body) {
                Ok(r) => {
                    Ok(r)
                },
                Err(_) => {
                    Err(warp::reject::custom(UnknownError))
                }
            }
        } else if middelware_res == *"Suspended" {
            Ok(warp::reply::with_status(warp::reply::json(
                &model::error::Error{
                    error: true,
                    message: "Account suspended".to_string(),
                }
            ),
            warp::http::StatusCode::FORBIDDEN))
        } else {
            Err(warp::reject::custom(UnknownError))
        }
    }))
    .or(warp::path("oauth2").and(warp::path("token")).and(warp::post()).and(warp::body::json()).map(router::oauth::get_oauth_code))
    .or(warp::path("oauth2").and(warp::post()).and(warp::body::json()).and(warp::header("authorization")).and_then(|body: model::body::OAuth, token: String| async {
        let middelware_res: String = middleware(Some(token), "@me").unwrap_or_else(|_| "Invalid".to_string());
        if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
            Ok(router::oauth::post(body, middelware_res))
        } else if middelware_res == "Suspended" {
            Ok(warp::reply::with_status(warp::reply::json(
                &model::error::Error{
                    error: true,
                    message: "Account suspended".to_string(),
                }
            ),
            warp::http::StatusCode::FORBIDDEN))
        } else {
            Err(warp::reject::custom(UnknownError))
        }
    }))
    .or(warp::path("users").and(warp::path("@me")).and(warp::delete()).and(warp::body::json()).and(warp::header("authorization")).and_then(|body: model::body::Gdrp, token: String| async {
        let middelware_res: String = middleware(Some(token), "@me").unwrap_or_else(|_| "Invalid".to_string());
        if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
            match  router::users::delete(middelware_res, body).await {
                Ok(r) => {
                    Ok(r)
                },
                Err(_) => {
                    Err(warp::reject::custom(UnknownError))
                }
            }
        } else if middelware_res == "Suspended" {
            Ok(warp::reply::with_status(warp::reply::json(
                &model::error::Error{
                    error: true,
                    message: "Account suspended".to_string(),
                }
            ),
            warp::http::StatusCode::FORBIDDEN))
        } else {
            Err(warp::reject::custom(UnknownError))
        }
    }))
    .or(warp::path("login").and(warp::path("recuperate")).and(warp::get()).and(warp::header("code")).and(warp::header("cf-turnstile-token")).and_then(|code: String, cf_token: String| async move {
        match router::login::recuperate::recuperate_account(code, cf_token).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    }))
    .or(warp::path("login").and(warp::path("security_token")).and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and(warp::addr::remote()).and(warp::header("authorization")).and_then(|body: model::body::TempToken, cf_token: String, ip: Option<SocketAddr>, token: String| async move {
        let middelware_res: String = middleware(Some(token), "@me").unwrap_or_else(|_| "Invalid".to_string());
        if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
            match router::login::token::temp_token(body, ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip(), cf_token, "t".to_string()).await {
                Ok(r) => {
                    Ok(r)
                },
                Err(_) => {
                    Err(warp::reject::custom(UnknownError))
                }
            }
        } else if middelware_res == "Suspended" {
            Ok(warp::reply::with_status(warp::reply::json(
                &model::error::Error{
                    error: true,
                    message: "Account suspended".to_string(),
                }
            ),
            warp::http::StatusCode::FORBIDDEN))
        } else {
            Err(warp::reject::custom(UnknownError))
        }
    }))
    .recover(handle_rejection);

    let port: u16 = dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap();
    println!("Server started on port {}", port);

    warp::serve(warp::any().and(warp::options()).map(|| "OK").or(warp::head().map(|| "OK")).or(routes))
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
        assert!(TOKEN.is_match("0ef32821-0b07-43a9-83b9-93f8e49253aa"));
    }
}
