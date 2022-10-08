use regex::Regex;
use warp::reply::{WithStatus, Json};
use sha256::digest;
use std::{thread, time};
use crate::database::cassandra::query;

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

    let user = &query("SELECT vanity, mfa_code, password FROM accounts.users WHERE email = ?", vec![digest(body.email)]).await.response_body().unwrap();
    let error = user.as_cols().unwrap().rows_content.is_empty() || !crate::helpers::hash_test(&vec_to_string(&user.as_cols().unwrap().rows_content[0][2].clone().into_bytes().unwrap())[..], body.password.as_ref());
    if error {
        thread::sleep(time::Duration::from_millis(200));
        warp::reply::with_status(warp::reply::json(
            &super::model::Error {
                error: true,
                message: "Invalid email or password".to_string()
            }
        ), warp::http::StatusCode::NOT_FOUND)
    } else {
        let vanity: String = vec_to_string(&user.as_cols().unwrap().rows_content[0][0].clone().into_bytes().unwrap());
        warp::reply::with_status(warp::reply::json(
            &super::model::CreateResponse{
                token: crate::helpers::create_jwt(vanity.to_lowercase(), Some(digest(&finger)), Some(crate::database::cassandra::create_security(vanity.to_lowercase(), crate::router::model::SecurityCode::Jwt as u8, finger, None, None).await.to_string())).await
            }
        ),
        warp::http::StatusCode::OK)
    }
}