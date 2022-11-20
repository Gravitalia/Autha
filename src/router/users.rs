use warp::reply::{WithStatus, Json};
use super::model;
use regex::Regex;
use crate::database::cassandra::query;

pub async fn get(id: String) -> WithStatus<Json> {
    let user = query("SELECT username, avatar, bio, verified, deleted, flags FROM accounts.users WHERE vanity = ?", vec![id.clone()]).await.rows.unwrap();

    if user.is_empty() {
        warp::reply::with_status(warp::reply::json(
            &model::Error {
                error: true,
                message: "Unknown user".to_string()
            }
        ), warp::http::StatusCode::NOT_FOUND)
    } else {
        warp::reply::with_status(warp::reply::json(
            &model::User {
                username: user[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string(),
                vanity: id,
                avatar: if user[0].columns[1].is_none() { None } else { Some(user[0].columns[1].as_ref().unwrap().as_text().unwrap().to_string()) },
                bio: if user[0].columns[2].is_none() { None } else { Some(user[0].columns[2].as_ref().unwrap().as_text().unwrap().to_string()) },
                verified: user[0].columns[3].as_ref().unwrap().as_boolean().unwrap(),
                deleted: user[0].columns[4].as_ref().unwrap().as_boolean().unwrap(),
                flags: user[0].columns[5].as_ref().unwrap().as_int().unwrap() as u32,
            }
        ), warp::http::StatusCode::OK)
    }
}

pub async fn patch(body: super::model::UserPatch, vanity: String) -> WithStatus<Json> {
    let mut is_psw_valid: bool = false;
    if body.password.is_some() {
        let psw = query("SELECT password FROM accounts.users WHERE vanity = ?", vec![vanity]).await.rows.unwrap();
        if !psw.is_empty() && crate::helpers::hash_test(&psw[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string()[..], body.password.unwrap().as_ref()) {
            is_psw_valid = true;
        } else {
            return super::err("Invalid password".to_string());
        }
    }

    // Check email
    if body.email.is_some() {
        if !is_psw_valid || !Regex::new(r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,7})$").unwrap().is_match(&body.email.unwrap_or("".to_string())) {
            return super::err("Invalid email".to_string());
        } else {
            // Save new email
        }
    }

    warp::reply::with_status(warp::reply::json(
        &model::Error{
            error: false,
            message: "OK".to_string(),
        }
    ),
    warp::http::StatusCode::OK)
}