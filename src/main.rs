mod model;
mod router;
mod helpers;
mod database;

#[macro_use] extern crate lazy_static;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::{Filter, reject::Reject, http::StatusCode, Reply};
use regex::Regex;

lazy_static! {
    static ref TOKEN: Regex = Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
}

#[derive(Debug)]
struct UnknownError;
impl Reject for UnknownError {}

async fn handle_rejection(_err: warp::Rejection) -> Result<impl Reply, std::convert::Infallible> {
    Ok(warp::reply::with_status(warp::reply::json(&model::error::Error {
        error: true,
        message: "Check the information provided".to_string(),
    }), StatusCode::BAD_REQUEST))
}

/// Check if a token is valid and if have a real user behind (not suspended)
fn middleware(token: Option<String>, fallback: &str) -> String {
    match &token {
        Some(ntoken) if fallback == "@me" => {
            if let Ok(data) = helpers::jwt::get_jwt(ntoken.clone()) {
                if let Ok(user) = database::cassandra::query("SELECT deleted FROM accounts.users WHERE vanity = ?", vec![data.claims.sub.clone()]) {
                    if let Some(row) = user.get_body().unwrap().as_cols().unwrap().rows_content.get(0) {
                        if row.get(0).unwrap().clone().into_plain().unwrap()[..] != [0] {
                            return "Suspended".to_string();
                        } else {
                            return data.claims.sub;
                        }
                    }
                }
                return data.claims.sub;
            }
            "Invalid".to_string()
        }
        None if fallback == "@me" => "Invalid".to_string(),
        _ => fallback.to_string(),
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

    //let _ = database::cassandra::create_bot("suba".to_string(), "TF5hobQgfPJSqs-QICYlDl9H1USn-vZ3".to_string(), "Suba".to_string());

    let routes = warp::path("create").and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and(warp::addr::remote()).and_then(|body: model::body::Create, cf_token: String, ip: Option<SocketAddr>| async move {
        match router::create::create(body, ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip(), cf_token).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    })
    .or(warp::path("login").and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and(warp::addr::remote()).and_then(|body: model::body::Login, cf_token: String, ip: Option<SocketAddr>| async move {
        match router::login::login(body, ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip(), cf_token).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    }))
    .or(warp::path!("users" / String).and(warp::get()).and(warp::header::optional::<String>("authorization")).and_then(|id: String, token: Option<String>| async move {
        if id == "@me" && token.is_some() && TOKEN.is_match(&token.clone().unwrap()) {
            let oauth = match database::cassandra::query("SELECT user_id FROM accounts.oauth WHERE id = ?", vec![token.unwrap()]) {
                Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
                Err(_) => {
                    return Err(warp::reject::custom(UnknownError));
                }
            };

            if oauth.is_empty() {
                Err(warp::reject::custom(UnknownError))
            } else {
                Ok(router::users::get(std::str::from_utf8(&oauth[0][0].clone().into_plain().unwrap()[..]).unwrap().to_string()))
            }
        } else {
            let middelware_res: String = middleware(token, &id);
            if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
                Ok(router::users::get(middelware_res.to_lowercase()))
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
        let middelware_res: String = middleware(Some(token), "@me");
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
        let middelware_res: String = middleware(Some(token), "@me");
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
        let middelware_res: String = middleware(Some(token), "@me");
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
    .recover(handle_rejection);

    let port: u16 = dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap();
    println!("Server started on port {}", port);

    warp::serve(warp::any().and(warp::options()).map(|| "OK").or(warp::any().and(warp::get()).map(|| {
        println!("Received");
        "OK"
    })).or(warp::head().map(|| "OK")).or(routes))
    .run((
        [0, 0, 0, 0],
        port,
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
