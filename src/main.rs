use warp::{Filter, reject::Reject};
use crate::database::cassandra::query;
mod router;
mod helpers;
mod database;

#[derive(Debug)]
struct InvalidQuery;
impl Reject for InvalidQuery {}

#[derive(Debug)]
struct UnknownError;
impl Reject for UnknownError {}

/// Check if a token is valid, have a real user behind (not suspended) and if the fingerprint
/// is valid
async fn middleware(token: Option<String>, fallback: String, finger: Option<String>) -> String {
    if token.is_some() && fallback == *"@me" {
        match helpers::get_jwt(token.unwrap()) {
            Ok(data) => {
                let user = query("SELECT deleted FROM accounts.users WHERE vanity = ?", vec![data.claims.sub.clone()]).await.rows.unwrap();
                if !user.is_empty() && user[0].columns[0].as_ref().unwrap().as_boolean().unwrap() {
                    "Suspended".to_string()
                } else if user.is_empty() || data.claims.aud.clone().unwrap_or_else(|| "".to_string()) != sha256::digest(&*finger.clone().unwrap_or_else(|| "none".to_string()))[0..24] {
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

    let routes = warp::path("create").and(warp::post()).and(warp::body::json()).and(warp::header("sec")).and(warp::header("cf-turnstile-token")).and_then(|body: router::model::Create, finger: String, _cf_token: String| async {
        match router::create::create(body, finger).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    })
    .or(warp::path!("users" / String).and(warp::get()).and(warp::header::optional::<String>("authorization")).and(warp::header::optional::<String>("sec")).and_then(|id: String, token: Option<String>, finger: Option<String>| async {
        let middelware_res: String = middleware(token, id, finger).await;
        if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
            Ok(router::users::get(middelware_res.to_lowercase()).await)
        } else if middelware_res == "Suspended" {
            Ok(warp::reply::with_status(warp::reply::json(
                &router::model::Error{
                    error: true,
                    message: "Account suspended".to_string(),
                }
            ),
            warp::http::StatusCode::FORBIDDEN))
        } else {
            Err(warp::reject::custom(InvalidQuery))
        }
    }))
    .or(warp::path("login").and(warp::post()).and(warp::body::json()).and(warp::header("sec")).and(warp::header("cf-turnstile-token")).and_then(|body: router::model::Login, finger: String, _cf_token: String| async {
        match router::login::login(body, finger).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    }))
    .or(warp::path!("users" / "@me").and(warp::patch()).and(warp::body::json()).and(warp::header("authorization")).and(warp::header("sec")).and_then(|body: router::model::UserPatch, token: String, finger: String| async {
        let middelware_res: String = middleware(Some(token), "@me".to_string(), Some(finger)).await;
        if middelware_res != *"Invalid" && middelware_res != *"Suspended" {
            Ok(router::users::patch(body, middelware_res).await)
        } else if middelware_res == "Suspended" {
            Ok(warp::reply::with_status(warp::reply::json(
                &router::model::Error{
                    error: true,
                    message: "Account suspended".to_string(),
                }
            ),
            warp::http::StatusCode::FORBIDDEN))
        } else {
            Err(warp::reject::custom(UnknownError))
        }
    }));

    database::cassandra::init().await;
    database::cassandra::tables().await;
    database::mem::init();
    helpers::init();

    warp::serve(warp::any().and(warp::options()).map(|| "OK").or(routes))
    .run((
        [127, 0, 0, 1],
        dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap(),
    ))
    .await;
}