use crate::{database::cassandra::query, helpers};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::reply::{WithStatus, Json};
use totp_lite::{totp_custom, Sha1};
use sha3::{Digest, Keccak256};
use crate::database::mem;
use anyhow::Result;

/// Handle create token route to allow sensitive data modification
pub async fn temp_token(body: crate::model::body::TempToken, ip: std::net::IpAddr, token: String, vanity: String) -> Result<WithStatus<Json>> {
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
        return Ok(crate::router::rate());
    }
    let _ = mem::set(ip, mem::SetValue::Number(rate_limit+1));
    
    // Check if account exists
    let query_res = match query("SELECT password, deleted, mfa_code FROM accounts.users WHERE vanity = ?", vec![vanity]) {
        Ok(x) => x.get_body()?.as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    };
    if query_res.is_empty() {
        return Ok(crate::router::err("Invalid user".to_string()));
    }

    // Check if account is deleted
    match query_res[0][2].clone().into_plain() {
        Some(d) => {
            if d == [1] {
                return Ok(crate::router::err("Account suspended".to_string()));
            }
        },
        None => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    let mut is_valid = false;

    // Check if user use password or 2FA
    if body.password.is_some() {
        match query_res[0][1].clone().into_plain() {
            Some(d) => {
                if !helpers::crypto::hash_test(std::str::from_utf8(&d[..])?, body.password.unwrap().as_bytes()) {
                    return Ok(crate::router::err("Invalid password".to_string()));
                } else {
                    is_valid = true;
                }
            },
            None => {
                return Ok(crate::router::err("Internal server error".to_string()));
            }
        }
    } else if body.mfa.is_some() && query_res[0][3].clone().into_plain().is_some() {
        match query_res[0][3].clone().into_plain() {
            Some(d) => {
                if totp_custom::<Sha1>(30, 6, helpers::crypto::decrypt(std::str::from_utf8(&d[..])?.to_string()).as_ref(), SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()) != body.mfa.unwrap()  {
                    return Ok(crate::router::err("Invalid MFA".to_string()));
                } else {
                    is_valid = true;
                }
            },
            None => {
                return Ok(crate::router::err("Internal server error".to_string()));
            }
        }
    }

    match helpers::request::check_turnstile(token).await {
        Ok(res) => {
            if !res {
                return Ok(crate::router::err("Invalid user".to_string()));
            }
        },
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    if !is_valid {
        return Ok(crate::router::err("Invalid password".to_string()));
    }

    // Finish and create a token for 5 minutes
    Ok(warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: false,
            message: mem::set(crate::helpers::random_string(23), mem::SetValue::Characters("ok".to_string()))?
        }
    ),
    warp::http::StatusCode::OK))
}
