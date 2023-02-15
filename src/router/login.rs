use crate::{database::cassandra::query, helpers};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::reply::{WithStatus, Json};
use totp_lite::{totp_custom, Sha1};
use sha3::{Digest, Keccak256};
use crate::database::mem;
use regex::Regex;
use tokio::task;

lazy_static! {
    static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
}

/// Handle login route and check if everything is valid
pub async fn login(body: crate::model::body::Login, ip: std::net::IpAddr) -> Result<WithStatus<Json>, memcache::MemcacheError> {
    let data = body.clone();
    let is_valid = task::spawn(async move {
        // Email verification
        if !EMAIL.is_match(&body.email) {
            return "Invalid email";
        }
        // Password checking [Security]
        if body.password.len() < 8 && !PASSWORD.is_match(&body.password) {
            return "Invalid password";
        }
        "ok"
    });
    let result = is_valid.await.unwrap();

    if result != "ok" {
        return Ok(super::err(result.to_string()));
    }

    // Hash IP
    let mut hasher = Keccak256::new();
    hasher.update(ip.to_string());
    let ip = hex::encode(&hasher.finalize()[..]);

    // Check if user have tried to login 5 minutes ago
    let rate_limit = match mem::get(ip.clone())? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 8 {
        return Ok(super::rate());
    }
    let _ = mem::set(ip, mem::SetValue::Number(rate_limit+1));

    // Hash email
    hasher = Keccak256::new();
    hasher.update(data.email.as_bytes());
    let hashed_email = hex::encode(&hasher.finalize()[..]);
    
    // Check if account exists
    let query_res = match query("SELECT vanity, password, deleted, mfa_code FROM accounts.users WHERE email = ?", vec![hashed_email]) {
        Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return Ok(super::err("Internal server error".to_string()));
        }
    };
    if query_res.is_empty() {
        return Ok(super::err("Invalid user".to_string()));
    }

    // Check if account is deleted
    match query_res[0][2].clone().into_plain() {
        Some(d) => {
            if d == [1] {
                return Ok(super::err("Account suspended".to_string()));
            }
        },
        None => {
            return Ok(super::err("Internal server error".to_string()));
        }
    }

    // Check if password is same
    match query_res[0][1].clone().into_plain() {
        Some(d) => {
            match std::str::from_utf8(&d[..]) {
                Ok(x) => {
                    if !helpers::hash_test(x, data.password.as_bytes()) {
                        return Ok(super::err("Invalid password".to_string()));
                    }
                },
                Err(_) => {
                    return Ok(super::err("Internal server error".to_string()));
                }
            }
        },
        None => {
            return Ok(super::err("Internal server error".to_string()));
        }
    }
    
    // Check if MFA is valid
    if let Some(d) = query_res[0][3].clone().into_plain() {
        if body.mfa.is_none() {
            return Ok(super::err("Invalid MFA".to_string()));
        }

        match std::str::from_utf8(&d[..]) {
            Ok(x) => {
                if totp_custom::<Sha1>(30, 6, helpers::decrypt(x.to_string()).as_ref(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) != body.mfa.unwrap()  {
                    return Ok(super::err("Invalid MFA".to_string()));
                }
            },
            Err(_) => {
                return Ok(super::err("Internal server error".to_string()));
            }
        }
    }

    let mut vanity: String = "".to_string();
    // Set vanity
    match query_res[0][0].clone().into_plain() {
        Some(d) => {
            match std::str::from_utf8(&d[..]) {
                Ok(x) => {
                    if !helpers::hash_test(x, data.password.as_bytes()) {
                        vanity = x.to_string();
                    }
                },
                Err(_) => {
                    return Ok(super::err("Internal server error".to_string()));
                }
            }
        },
        None => {
            return Ok(super::err("Internal server error".to_string()));
        }
    }

    // Finish, create a JWT token and sent it
    Ok(warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: false,
            message: crate::helpers::create_jwt(vanity),
        }
    ),
    warp::http::StatusCode::OK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex() {
        assert!(EMAIL.is_match("foo@🏹.to"));
        assert!(PASSWORD.is_match("Test1234_"));
    }
}