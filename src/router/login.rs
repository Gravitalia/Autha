use regex::Regex;
use warp::reply::{WithStatus, Json};
use sha256::digest;
use std::{time::{SystemTime, UNIX_EPOCH}};
use totp_lite::{totp_custom, Sha1};
use crate::database::cassandra::query;
use crate::database::mem;

fn vec_to_string(vec: &[u8]) -> String {
    String::from_utf8_lossy(vec).to_string()
}

pub async fn login(body: super::model::Login, finger: String) -> WithStatus<Json> {
    // Email verification
    if !Regex::new(r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,7})$").unwrap().is_match(&body.email) {
        return super::err("Invalid email".to_string());
    }
    // Password checking [Security]
    if !Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap().is_match(&body.password) {
        return super::err("Invalid password".to_string());
    }

    let rate_limit = mem::get(digest(&body.email)).unwrap().unwrap_or("0".to_string()).parse::<u16>().unwrap();
    if rate_limit >= 5 {
        return warp::reply::with_status(warp::reply::json(
            &super::model::Error{
                error: true,
                message: "Rate limited (5 failures in less than 5 seconds)".to_string()
            }
        ),
        warp::http::StatusCode::TOO_MANY_REQUESTS);
    }

    let user = &query("SELECT vanity, mfa_code, password FROM accounts.users WHERE email = ?", vec![digest(&body.email)]).await.response_body().unwrap();
    if user.as_cols().unwrap().rows_content.is_empty() || !crate::helpers::hash_test(&vec_to_string(&user.as_cols().unwrap().rows_content[0][2].clone().into_bytes().unwrap())[..], body.password.as_ref()) {
        let _ = mem::set(digest(body.email), mem::SetValue::Number(rate_limit+1));
        return super::err("Invalid email or password".to_string());
    }

    let mfa_code: Option<String> = user.as_cols().unwrap().rows_content[0][1].clone().into_bytes().map(|value| String::from_utf8_lossy(&value).to_string());
    if mfa_code.is_some() && body.mfa.is_none() {
        return super::err("MFA".to_string());
    } else if mfa_code.is_some() && body.mfa.is_some() {
        // Save MFA code in clear, not in base32
        if totp_custom::<Sha1>(30, 6, mfa_code.unwrap().as_ref(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) != body.mfa.unwrap() {
            return super::err("MFA".to_string());
        }
    }

    let vanity: String = vec_to_string(&user.as_cols().unwrap().rows_content[0][0].clone().into_bytes().unwrap());
    warp::reply::with_status(warp::reply::json(
        &super::model::CreateResponse{
            token: crate::helpers::create_jwt(vanity.to_lowercase(), Some(digest(&finger)), Some(crate::database::cassandra::create_security(vanity.to_lowercase(), crate::router::model::SecurityCode::Jwt as u8, finger, None, None).await.to_string())).await
        }
    ), warp::http::StatusCode::OK)
}