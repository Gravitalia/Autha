mod model;
mod router;
mod helpers;
mod database;
#[macro_use] extern crate lazy_static;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::{Filter, reject::Reject, http::StatusCode, Reply};

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
fn middleware(token: Option<String>, fallback: String) -> String {
    if let Some(ntoken) = token {
        if fallback != *"@me" {
            return fallback;
        }

        match helpers::get_jwt(ntoken) {
            Ok(data) => {
                let user = match database::cassandra::query("SELECT deleted FROM accounts.users WHERE vanity = ?", vec![data.claims.sub.clone()]) {
                    Ok(data) => data.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
                    Err(_) => {
                        return data.claims.sub;
                    }
                };
                if !user.is_empty() && user[0][0].clone().into_plain().unwrap()[..] != [0] {
                    "Suspended".to_string()
                } else if user.is_empty() {
                    "Invalid".to_string()
                } else {
                    data.claims.sub
                }
            },
            Err(_) => "Invalid".to_string()
        }
    } else if fallback == *"@me" {
        "Invalid".to_string()
    } else {
        fallback
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    database::cassandra::init();
    database::cassandra::create_tables();
    let _ = database::mem::init();

    //let _ = database::cassandra::create_bot("suba".to_string(), "TF5hobQgfPJSqs-QICYlDl9H1USn-vZ3".to_string(), "Suba".to_string());

    let routes = warp::path("create").and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and(warp::addr::remote()).and_then(|body: model::body::Create, _cf_token: String, ip: Option<SocketAddr>| async move {
        match router::create::create(body, ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip()).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    })
    .or(warp::path("login").and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and(warp::addr::remote()).and_then(|body: model::body::Login, _cf_token: String, ip: Option<SocketAddr>| async move {
        match router::login::login(body, ip.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)).ip()).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    }))
    .or(warp::path!("users" / String).and(warp::get()).and(warp::header::optional::<String>("authorization")).and_then(|id: String, token: Option<String>| async {
        if id == "@me" && token.is_some() && regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap().is_match(&token.clone().unwrap()) {
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
            let middelware_res: String = middleware(token, id);
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
        let middelware_res: String = middleware(Some(token), "@me".to_string());
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
        let middelware_res: String = middleware(Some(token), "@me".to_string());
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
    .recover(handle_rejection);

    let cors = warp::cors()
                        .allow_any_origin()
                        .allow_methods(vec!["GET", "POST", "DELETE", "PATCH"]);

    warp::serve(warp::any().and(warp::options()).map(|| "OK").or(warp::head().map(|| "OK")).or(routes).with(cors))
    .run((
        [127, 0, 0, 1],
        dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap(),
    ))
    .await;
}