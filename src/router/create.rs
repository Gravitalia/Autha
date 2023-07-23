use std::sync::Arc;

use crate::database::scylla::{query, create_user};
use warp::reply::{WithStatus, Json};
use sha3::{Digest, Keccak256};
use crate::database::mem;
use crate::helpers;
use anyhow::Result;
use regex::Regex;
use tokio::task;

lazy_static! {
    static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    static ref VANITY: Regex = Regex::new(r"[A-z|0-9|_]{3,16}$").unwrap();
    static ref PHONE: Regex = Regex::new(r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$").unwrap();
    static ref BIRTH: Regex = Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

/// Handle create route and check if everything is valid
pub async fn create(scylla: Arc<scylla::Session>, memcached: memcache::Client, body: crate::model::body::Create, ip: String, token: String) -> Result<WithStatus<Json>> {
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
        // Vanity verification
        if !VANITY.is_match(&body.vanity) || body.vanity.chars().all(|c| c.is_ascii_digit()) {
            return "Invalid vanity";
        }
        // Username checking
        if body.username.len() > 25 {
            return "Invalid username";
        }
        
        "ok"
    });
    let result = is_valid.await?;

    if result != "ok" {
        return Ok(super::err(result.to_string()));
    }

    // Hash IP
    let mut hasher = Keccak256::new();
    hasher.update(ip.clone());
    let new_ip = hex::encode(&hasher.finalize()[..]);

    // Check if user have already created account 5 minutes ago
    let rate_limit = match mem::get(memcached.clone(), format!("account_create_{}", new_ip.clone()))? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 1 {
        return Ok(super::rate());
    }

    // Check if CF Turnstile token is valid
    match helpers::request::check_turnstile(token).await {
        Ok(res) => {
            if !res {
                return Ok(super::err("Invalid user".to_string()));
            }
        },
        Err(_) => {
            return Ok(super::err("Internal server error".to_string()));
        }
    }

    // Hash email
    let hashed_email = helpers::crypto::fpe_encrypt(data.email.encode_utf16().collect())?;

    let mut query_res: Vec<scylla::_macro_internal::Row>;
    // Check if account with this email and vanity already exists
    query_res = query(Arc::clone(&scylla), "SELECT vanity FROM accounts.users WHERE email = ?;", vec![hashed_email.clone()])
                    .await?
                    .rows
                    .unwrap_or_default();

    if !query_res.is_empty() {
        return Ok(super::err("Email already used".to_string()));
    }

    // Check if vanity is already used
    query_res = query(Arc::clone(&scylla), "SELECT vanity FROM accounts.users WHERE vanity = ?;", vec![data.vanity.clone()])
                    .await?
                    .rows
                    .unwrap_or_default();

    // Check if bot id is already used
    if query_res.is_empty() {
        query_res = query(Arc::clone(&scylla),"SELECT id FROM accounts.bots WHERE id = ?", vec![data.vanity.clone()])
                        .await?
                        .rows
                        .unwrap_or_default();
    }

    if !query_res.is_empty() || [ "explore", "callback", "home", "blogs", "blog", "gravitalia", "suba", "support", "oauth", "upload", "new", "settings", "parameters", "fallback" ].contains(&data.vanity.as_str()) {
        return Ok(super::err("Vanity already used".to_string()));
    }

    // Phone verification
    let mut phone: Option<String> = None;
    if body.phone.is_some() {
        if !PHONE.is_match(body.phone.as_ref().unwrap_or(&"".to_string())) {
            return Ok(super::err("Invalid phone".to_string()));
        } else {
            phone = Some(helpers::crypto::encrypt(Arc::clone(&scylla), body.phone.unwrap_or_default().as_bytes()).await);
        }
    }
    // Birthdate verification
    let mut birth: Option<String> = None;
    if body.birthdate.is_some() {
        let birthdate = body.birthdate.clone().unwrap_or_default();
        let dates: Vec<&str> = birthdate.split('-').collect();

        if !birthdate.is_empty() && (!BIRTH.is_match(body.birthdate.as_ref().unwrap_or(&"".to_string())) || 13 > helpers::get_age(dates[0].parse::<i32>().unwrap_or_default(), dates[1].parse::<u32>().unwrap_or_default(), dates[2].parse::<u32>().unwrap_or_default()) as i32) {
            return Ok(super::err("Invalid birthdate".to_string()));
        } else {
            birth = Some(helpers::crypto::encrypt(Arc::clone(&scylla), body.birthdate.unwrap_or_default().as_bytes()).await);
        }
    }

    // Create account
    match create_user(Arc::clone(&scylla), &data.vanity, hashed_email, data.username, helpers::crypto::hash(data.password.as_bytes()), phone, birth).await {
        Ok(_) => {},
        Err(e) => {
            eprintln!("(create) Cannot create user: {}", e);
            return Ok(super::err("Internal server error".to_string()));
        }
    }
    
    let _ = mem::set(memcached, format!("account_create_{}", new_ip), mem::SetValue::Number(1));

    // Finish, create a JWT token and sent it
    Ok(warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: false,
            message: helpers::token::create(scylla, data.vanity, ip).await?,
        }
    ),
    warp::http::StatusCode::CREATED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex() {
        assert!(EMAIL.is_match("foo@🏹.to"));
        assert!(PASSWORD.is_match("Password1234._"));
        assert!(VANITY.is_match("realhinome"));
        assert!(PHONE.is_match("0000000000"));
        assert!(BIRTH.is_match("2000-01-01"));
    }
}