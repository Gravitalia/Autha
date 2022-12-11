use regex::Regex;
use warp::reply::{WithStatus, Json};
use sha256::digest;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp_custom, Sha1};
use crate::database::cassandra::query;
use crate::database::mem;

pub async fn login(body: super::model::Login, finger: String, req_query: super::model::LoginQuery) -> Result<WithStatus<Json>, memcache::MemcacheError> {
    // Email verification
    if !Regex::new(r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,7})$").unwrap().is_match(&body.email) {
        return Ok(super::err("Invalid email".to_string()));
    }
    // Password checking [Security]
    if !Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap().is_match(&body.password) {
        return Ok(super::err("Invalid password".to_string()));
    }

    let rate_limit = match mem::get(digest(&*body.email))? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 8 {
        return Ok(warp::reply::with_status(warp::reply::json(
            &super::model::Error{
                error: true,
                message: "Rate limited (8 failures in less than 5 seconds)".to_string()
            }
        ),
        warp::http::StatusCode::TOO_MANY_REQUESTS));
    }

    let user = query("SELECT vanity, mfa_code, password, deleted, username, avatar FROM accounts.users WHERE email = ?", vec![digest(&*body.email)]).await.rows.unwrap();
    if user.is_empty() {
        return Ok(super::err("Invalid email".to_string()));
    } else if !crate::helpers::hash_test(&user[0].columns[2].as_ref().unwrap().as_text().unwrap().to_string()[..], body.password.as_ref()) {
        let _ = mem::set(digest(body.email), mem::SetValue::Number(rate_limit+1));
        if req_query.user.unwrap_or(false) {
            return Ok(warp::reply::with_status(warp::reply::json(
                &super::model::User{
                    username: user[0].columns[4].as_ref().unwrap().as_text().unwrap().to_string(),
                    vanity: user[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string(),
                    avatar: if user[0].columns[5].is_none() { None } else { Some(user[0].columns[1].as_ref().unwrap().as_text().unwrap().to_string()) },
                    bio: None,
                    verified: false,
                    deleted: false,
                    flags: 0
                }
            ), warp::http::StatusCode::OK));
        } else {
            return Ok(super::err("Invalid password".to_string()));
        }
    } else if user[0].columns[3].as_ref().unwrap().as_boolean().unwrap() {
        return Ok(warp::reply::with_status(warp::reply::json(
            &super::model::Error{
                error: true,
                message: "Account suspended".to_string(),
            }
        ),
        warp::http::StatusCode::FORBIDDEN));
    }

    let mfa_code: Option<String> = if user[0].columns[1].is_none() { None } else { Some(user[0].columns[1].as_ref().unwrap().as_text().unwrap().to_string()) };
    if mfa_code.is_some() && body.mfa.is_none() {
        return Ok(super::err("MFA".to_string()));
    } else if mfa_code.is_some() && body.mfa.is_some() {
        // Save MFA code in clear, not in base32
        if totp_custom::<Sha1>(30, 6, mfa_code.unwrap().as_ref(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) != body.mfa.unwrap() {
            return Ok(super::err("MFA".to_string()));
        }
    }

    let vanity: String = user[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string();
    Ok(warp::reply::with_status(warp::reply::json(
        &super::model::CreateResponse{
            token: crate::helpers::create_jwt(vanity.to_lowercase(), Some(digest(&*finger)), Some(crate::database::cassandra::create_security(vanity.to_lowercase(), crate::router::model::SecurityCode::Jwt as u8, finger, None, None).await.to_string()))
        }
    ), warp::http::StatusCode::OK))
}