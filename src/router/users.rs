use warp::reply::{WithStatus, Json};
use crate::database::cassandra::{query, suspend};
use super::model;
use regex::Regex;
use sha256::digest;

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
        let psw = query("SELECT password FROM accounts.users WHERE vanity = ?", vec![vanity.clone()]).await.rows.unwrap();
        if !psw.is_empty() && crate::helpers::hash_test(&psw[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string()[..], body.password.unwrap().as_ref()) {
            is_psw_valid = true;
        } else {
            return super::err("Invalid password".to_string());
        }
    }

    // Change username
    if body.username.is_some() {
        let username = match body.username {
            Some(u) => u,
            None => "".to_string()
        };

        if username.len() >= 16 {
            return super::err("Invalid username".to_string());
        } else {
            query("UPDATE accounts.users SET username = ? WHERE vanity = ?", vec![username, vanity.clone()]).await;
        }
    }

    // Change bio
    if body.bio.is_some() {
        let bio = match body.bio {
            Some(b) => b,
            None => "".to_string()
        };

        if bio.len() > 255 {
            return super::err("Invalid bio".to_string());
        } else {
            query("UPDATE accounts.users SET bio = ? WHERE vanity = ?", vec![bio, vanity.clone()]).await;
        }
    }

    // Change email
    if body.email.is_some() {
        let email = match body.email {
            Some(e) => e,
            None => "".to_string()
        };

        if !is_psw_valid || !Regex::new(r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,7})$").unwrap().is_match(&email) {
            return super::err("Invalid email".to_string());
        } else {
            query("UPDATE accounts.users SET email = ? WHERE vanity = ?", vec![digest(&*email), vanity.clone()]).await;
        }
    }

    // Change birthdate
    if body.birthdate.is_some() {
        let birth = match body.birthdate {
            Some(b) => b,
            None => "".to_string()
        };

        if !Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap().is_match(&birth) {
            return super::err("Invalid birthdate".to_string());
        } else {
            let dates: Vec<&str> = birth.split('-').collect();

            if 13 > crate::helpers::get_age(dates[0].parse::<i32>().unwrap(), dates[1].parse::<u32>().unwrap(), dates[2].parse::<u32>().unwrap()) as i32 {
                suspend(vanity.clone()).await;
            } else {
                query("UPDATE accounts.users SET birthdate = ? WHERE vanity = ?", vec![crate::helpers::encrypt(birth.as_bytes()), vanity.clone()]).await;
            }
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