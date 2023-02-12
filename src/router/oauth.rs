use crate::database::{cassandra::{query, create_oauth}, mem::{set, get, SetValue::Characters}};
use crate::helpers::random_string;
use warp::reply::{WithStatus, Json};

/// Handle post request for /oauth
pub fn post(body: crate::model::body::OAuth, vanity: String) -> WithStatus<Json> {
    let bot = match query("SELECT flags, deleted, redirect_url FROM accounts.bots WHERE id = ?", vec![body.bot_id.clone()]) {
        Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return super::err("Internal server error".to_string());
        }
    };

    // Check if bot exists or deleted
    if bot.is_empty() {
        return super::err("Invalid bot_id".to_string());
    } else if bot[0][1].clone().into_plain().unwrap()[..] == [1] {
        return super::err("This bot has been deleted".to_string());
    }
    // Check if the redirect_url is valid
    if !std::str::from_utf8(&bot[0][2].clone().into_plain().unwrap()[..]).unwrap().to_string().replace("\u{2}\0\0\0\u{1d}", "").replace("\0\0\0", "").split('#').any(|x| x == &body.redirect_uri[..]) {
        return super::err("Invalid redirect_uri".to_string());
    }

    // If empty, tries to find a valid code
    if body.response_type.is_empty() {
        let res = match query("SELECT id, bot_id FROM accounts.oauth WHERE user_id = ?", vec![vanity.clone()]) {
            Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
            Err(_) => {
                return super::err("Internal server error".to_string());
            }
        };

       if res.is_empty() {
            super::err("".to_string())
        } else {
            if res.iter().filter(|x| *std::str::from_utf8(&x[1].clone().into_plain().unwrap()[..]).unwrap() == body.bot_id).map(|x| std::str::from_utf8(&x[0].clone().into_plain().unwrap()[..]).unwrap().to_string()).collect::<String>().is_empty() {
                return super::err("".to_string());
            }

            let id = random_string(24);
            let _ = set(id.clone(), Characters(format!("{}+{}+{}", body.bot_id, body.redirect_uri, vanity)));

            warp::reply::with_status(warp::reply::json(
                &crate::model::error::Error {
                    error: false,
                    message: id,
                }
            ),
            warp::http::StatusCode::OK)
        }
    } else if body.scope.split_whitespace().filter(|x| !["identity"].contains(x)).any(|_| true) {
        super::err("Invalid scope".to_string())
    } else {
        let id = random_string(24);
        let _ = set(id.clone(), Characters(format!("{}+{}+{}", body.bot_id, body.redirect_uri, vanity)));

        warp::reply::with_status(warp::reply::json(
            &crate::model::error::Error {
                error: false,
                message: id,
            }
        ),
        warp::http::StatusCode::OK)
    }
}

pub fn get_oauth_code(body: crate::model::body::GetOAuth) -> WithStatus<Json> {
    let data = match get(body.code).unwrap() {
        Some(r) => Vec::from_iter(r.split('+').map(|x| x.to_string())),
        None => vec![],
    };
    if data.is_empty() {
        return super::err("Invalid code".to_string());
    }
    let user_id = &data[2];

    if *data[0] != body.client_id {
        return super::err("Invalid client_id".to_string());
    }

    let bot = match query("SELECT flags, deleted, redirect_url FROM accounts.bots WHERE id = ?", vec![body.client_id.clone()]) {
        Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return super::err("Internal server error".to_string());
        }
    };

    // Check if bot exists or deleted
    if bot.is_empty() {
        return super::err("Invalid client_id".to_string());
    } else if bot[0][1].clone().into_plain().unwrap()[..] == [1] {
        return super::err("This bot has been deleted".to_string());
    }
    // Check if the redirect_url is valid
    if !std::str::from_utf8(&bot[0][2].clone().into_plain().unwrap()[..]).unwrap().to_string().replace("\u{2}\0\0\0\u{1d}", "").replace("\0\0\0", "").split('#').any(|x| x == &body.redirect_uri[..]) {
        return super::err("Invalid redirect_uri".to_string());
    }

    let res = match query("SELECT id, bot_id FROM accounts.oauth WHERE user_id = ?", vec![user_id.to_string()]) {
        Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return super::err("Internal server error".to_string());
        }
    };
    if res.is_empty() {
        warp::reply::with_status(warp::reply::json(
            &crate::model::error::Error {
                error: false,
                message: create_oauth(user_id.to_string(), body.client_id, /*body.scope.split_whitespace().map(|s| s.to_string()).collect()*/vec!["identity".to_string()]),
            }
        ),
        warp::http::StatusCode::CREATED)
    } else {
        let mut code = res.iter().filter(|x| *std::str::from_utf8(&x[1].clone().into_plain().unwrap()[..]).unwrap() == body.client_id).map(|x| std::str::from_utf8(&x[0].clone().into_plain().unwrap()[..]).unwrap().to_string());
        if code.clone().collect::<String>().is_empty() {
            warp::reply::with_status(warp::reply::json(
                &crate::model::error::Error {
                    error: false,
                    message: create_oauth(user_id.to_string(), body.client_id, /*body.scope.split_whitespace().map(|s| s.to_string()).collect()*/vec!["identity".to_string()]),
                }
            ),
            warp::http::StatusCode::CREATED)
        } else {
            warp::reply::with_status(warp::reply::json(
                &crate::model::error::Error {
                    error: false,
                    message: code.next().unwrap_or_default(),
                }
            ),
            warp::http::StatusCode::OK)
        }
    }
}