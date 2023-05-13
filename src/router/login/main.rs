use crate::{database::cassandra::query, helpers};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::reply::{WithStatus, Json};
use totp_lite::{totp_custom, Sha1};
use sha3::{Digest, Keccak256};
use crate::database::mem;
use anyhow::Result;
use regex::Regex;
use tokio::task;

lazy_static! {
    static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
}

/// Handle login route and check if everything is valid
pub async fn login(body: crate::model::body::Login, ip: String, token: String) -> Result<WithStatus<Json>> {
    let data = body.clone();
    let is_valid = task::spawn(async move {
        // Email verification
        if !EMAIL.is_match(&body.email) {
            return "Invalid email";
        }
        // Password checking [Security]
        if body.password != "testemail" && body.password.len() < 8 && !PASSWORD.is_match(&body.password) {
            return "Invalid password";
        }
        "ok"
    });
    let result = is_valid.await?;

    if result != "ok" {
        return Ok(crate::router::err(result.to_string()));
    }

    // Hash IP
    let mut hasher = Keccak256::new();
    hasher.update(ip.clone());
    let new_ip = hex::encode(&hasher.finalize()[..]);

    // Check if user have tried to login 5 minutes ago
    let rate_limit = match mem::get(format!("account_login_{}", new_ip.clone()))? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 5 {
        return Ok(crate::router::rate());
    }
    let _ = mem::set(new_ip, mem::SetValue::Number(rate_limit+1));

    // Hash email
    hasher = Keccak256::new();
    hasher.update(data.email.as_bytes());
    let hashed_email = hex::encode(&hasher.finalize()[..]);
    
    // Check if account exists
    let query_res = match query("SELECT vanity, password, deleted, mfa_code, expire_at FROM accounts.users WHERE email = ?", vec![hashed_email]) {
        Ok(x) => x.get_body()?.as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    };
    if query_res.is_empty() {
        return Ok(crate::router::err("Invalid user".to_string()));
    } else if data.password == "testemail" {
        return Ok(crate::router::err("Invalid password".to_string()));
    }

    // Set vanity
    let vanity = match query_res[0][0].clone().into_plain() {
        Some(d) => {
            std::str::from_utf8(&d[..])?.to_string()
        },
        None => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    };

    let expire = match query_res[0][4].clone().into_plain() {
        Some(d) => {
            u64::from_be_bytes(d.try_into().unwrap_or_default())
        },
        None => {
            0
        }
    };

    // Check if account is deleted
    match query_res[0][2].clone().into_plain() {
        Some(d) => {
            let timestamp_ms: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().try_into()?;

            if d == [1] && expire >= timestamp_ms {
                let recup_acc_id = helpers::random_string(37);
                mem::set(recup_acc_id.clone(), mem::SetValue::Characters(vanity.clone()))?;
                return Ok(crate::router::err(format!("Deleted account {} the {} recuperate with {}", vanity, expire, recup_acc_id)));
            } else if d == [1] && expire <= timestamp_ms {
                return Ok(crate::router::err("Invalid email".to_string()));
            } else if d == [1] && expire == 0 {
                return Ok(crate::router::err("Account suspended".to_string()));
            }
        },
        None => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    // Check if password is same
    match query_res[0][1].clone().into_plain() {
        Some(d) => {
            if !helpers::crypto::hash_test(std::str::from_utf8(&d[..])?, data.password.as_bytes()) {
                return Ok(crate::router::err("Invalid password".to_string()));
            }
        },
        None => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }
    
    // Check if MFA is valid
    if let Some(d) = query_res[0][3].clone().into_plain() {
        if body.mfa.is_none() {
            return Ok(crate::router::err("Invalid MFA".to_string()));
        }
        // Save MFA code in clear, not in base32 => for generate key, use helpers::random_string with 10 as length
        if totp_custom::<Sha1>(30, 6, helpers::crypto::decrypt(std::str::from_utf8(&d[..])?.to_string()).as_ref(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) != body.mfa.unwrap()  {
            return Ok(crate::router::err("Invalid MFA".to_string()));
        }
    }

    // Check if provided security header is ok
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

    // Finish, create a JWT token and sent it
    Ok(warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: false,
            message: helpers::jwt::create_jwt(vanity),
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
