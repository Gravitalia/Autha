use crate::database::cassandra::{query, create_user};
use warp::reply::{WithStatus, Json};
use sha3::{Digest, Keccak256};
use crate::database::mem;
use crate::helpers;
use regex::Regex;
use tokio::task;

lazy_static! {
    static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    static ref VANITY: Regex = Regex::new(r"[A-z|0-9|_]{3,16}").unwrap();
    static ref PHONE: Regex = Regex::new(r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$").unwrap();
    static ref BIRTH: Regex = Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

/// Handle create route and check if everything is valid
pub async fn create(body: crate::model::body::Create, ip: String, token: String) -> Result<WithStatus<Json>, memcache::MemcacheError> {
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
        if !VANITY.is_match(&body.vanity) {
            return "Invalid vanity";
        }
        // Username checking
        if body.username.len() >= 16 {
            return "Invalid username";
        }
        "ok"
    });
    let result = is_valid.await.unwrap();

    if result != "ok" {
        return Ok(super::err(result.to_string()));
    }

    // Hash IP
    let mut hasher = Keccak256::new();
    hasher.update(ip);
    let new_ip = hex::encode(&hasher.finalize()[..]);

    // Check if user have already created account 5 minutes ago
    let rate_limit = match mem::get(format!("account_create_{}", new_ip.clone()))? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 1 {
        return Ok(super::rate());
    }

    // Hash email
    hasher = Keccak256::new();
    hasher.update(data.email.as_bytes());
    let hashed_email = hex::encode(&hasher.finalize()[..]);
    
    // Check if account with this email and vanity already exists
    let mut query_res = match query("SELECT vanity FROM accounts.users WHERE email = ?", vec![hashed_email.clone()]) {
        Ok(x) => x.get_body().unwrap().into_rows().unwrap(),
        Err(_) => {
            return Ok(super::err("Internal server error".to_string()));
        }
    };
    if !query_res.is_empty() {
        return Ok(super::err("Email already used".to_string()));
    }

    // Check if vanity is already used
    query_res = match query("SELECT vanity FROM accounts.users WHERE vanity = ?", vec![data.vanity.clone()]) {
        Ok(x) => x.get_body().unwrap().into_rows().unwrap(),
        Err(_) => {
            return Ok(super::err("Internal server error".to_string()));
        }
    };

    // Check if bot id is already used
    if query_res.is_empty() {
        query_res = match query("SELECT id FROM accounts.bots WHERE id = ?", vec![data.vanity.clone()]) {
            Ok(x) => x.get_body().unwrap().into_rows().unwrap(),
            Err(_) => {
                return Ok(super::err("Internal server error".to_string()));
            }
        };
    }

    if !query_res.is_empty() {
        return Ok(super::err("Vanity already used".to_string()));
    }

    // Phone verification
    let mut phone: Option<String> = None;
    if body.phone.is_some() {
        if !PHONE.is_match(body.phone.as_ref().unwrap()) {
            return Ok(super::err("Invalid phone".to_string()));
        } else {
            phone = Some(helpers::crypto::encrypt(body.phone.unwrap().as_bytes()));
        }
    }
    // Birthdate verification
    let mut birth: Option<String> = None;
    if body.birthdate.is_some() {
        let birthdate = body.birthdate.clone().unwrap_or_default();
        let dates: Vec<&str> = birthdate.split('-').collect();

        if !birthdate.is_empty() && !BIRTH.is_match(body.birthdate.as_ref().unwrap()) || 13 > helpers::get_age(dates[0].parse::<i32>().unwrap(), dates[1].parse::<u32>().unwrap(), dates[2].parse::<u32>().unwrap()) as i32 {
            return Ok(super::err("Invalid birthdate".to_string()));
        } else {
            birth = Some(helpers::crypto::encrypt(body.birthdate.unwrap().as_bytes()));
        }
    }

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

    // Create account
    match create_user(&data.vanity, hashed_email, data.username, helpers::crypto::hash(data.password.as_bytes()), phone, birth) {
        Ok(_) => {},
        Err(_) => {
            return Ok(super::err("Internal server error".to_string()));
        }
    }
    
    let _ = mem::set(new_ip, mem::SetValue::Number(1));

    // Finish, create a JWT token and sent it
    Ok(warp::reply::with_status(warp::reply::json(
        &crate::model::error::Error{
            error: false,
            message: helpers::jwt::create_jwt(data.vanity),
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
        assert!(PASSWORD.is_match("Test1234_"));
        assert!(VANITY.is_match("realhinome"));
        assert!(PHONE.is_match("0000000000"));
        assert!(BIRTH.is_match("2000-01-01"));
    }
}
