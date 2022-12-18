use crate::database::cassandra::{query, create_oauth};
use warp::reply::{WithStatus, Json};
use std::collections::HashSet;

/// Handle post request for /oauth
pub async fn post(body: super::model::OAuth, vanity: String) -> WithStatus<Json> {
    let bot = query("SELECT flags, deleted, redirect_url FROM accounts.bots WHERE id = ?", vec![body.bot_id.clone()]).await.rows.unwrap();
    // Check if bot exists or deleted
    if bot.is_empty() {
        return super::err("Invalid bot_id".to_string());
    } else if bot[0].columns[1].as_ref().unwrap().as_boolean().unwrap() {
        return super::err("This bot has been deleted".to_string());
    }
    // Check if the redirect_url is valid
    if !bot[0].columns[2].clone().unwrap().as_set().unwrap().iter().map(|x| x.as_text().unwrap()).collect::<HashSet<_>>().contains(&body.redirect_uri) {
        return super::err("Invalid redirect_uri".to_string());
    }

    // If empty, tries to find a valid code
    if body.response_type.is_empty() {
        let res = query("SELECT id, bot_id FROM accounts.oauth WHERE user_id = ?", vec![vanity]).await.rows.unwrap();

        if res.is_empty() {
            super::err("".to_string())
        } else {
            let mut code = res.iter().filter(|x| *x.columns[1].as_ref().unwrap().as_text().unwrap() == body.bot_id).map(|x| x.columns[0].as_ref().unwrap().as_text().unwrap().to_string());
            if code.clone().collect::<String>().is_empty() {
                return super::err("".to_string());
            }

            warp::reply::with_status(warp::reply::json(
                &super::model::Error{
                    error: false,
                    message: code.next().unwrap_or_else(|| "".to_string()),
                }
            ),
            warp::http::StatusCode::OK)
        }
    } else if body.scope.split_whitespace().filter(|x| !["identity"].contains(x)).any(|_| true) {
        super::err("Invalid scope".to_string())
    } else {
        let id = create_oauth(vanity, body.bot_id, body.scope.split_whitespace().map(|s| s.to_string()).collect()).await;

        warp::reply::with_status(warp::reply::json(
            &super::model::Error{
                error: false,
                message: id.to_string(),
            }
        ),
        warp::http::StatusCode::OK)
    }
}