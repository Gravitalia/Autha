use crate::{database::{get_user, mem::{set, del, get as mem_get, SetValue}, cassandra::{update_user, query, suspend}}, model::{user::User, error::Error}};
use crate::helpers::{crypto::{encrypt, hash}, request::delete_account};
use warp::reply::{WithStatus, Json};
use sha3::{Digest, Keccak256};
use anyhow::Result;
use regex::Regex;

lazy_static! {
    static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    static ref BIRTH: Regex = Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

/// Handle GET users route
pub fn get(vanity: String) -> WithStatus<Json> {
    let user: User = match get_user(vanity.clone()) {
        Ok(d) => d,
        Err(_) => {
            return warp::reply::with_status(warp::reply::json(
                &Error {
                    error: true,
                    message: "Unknown user".to_string()
                }
            ), warp::http::StatusCode::NOT_FOUND);
        }
    };

    if user.vanity.is_empty() {
        warp::reply::with_status(warp::reply::json(
            &Error {
                error: true,
                message: "Unknown user".to_string()
            }
        ), warp::http::StatusCode::NOT_FOUND)
    } else if user.deleted {
        warp::reply::with_status(warp::reply::json(
            &User {
                username: "Deleted suspended".to_string(),
                vanity,
                avatar: None,
                bio: None,
                verified: false,
                deleted: true,
                flags: 0,
            }
        ), warp::http::StatusCode::OK)
    } else {
        let _ = set(vanity, SetValue::Characters(serde_json::to_string(&user).unwrap()));

        warp::reply::with_status(warp::reply::json(
            &user
        ), warp::http::StatusCode::OK)
    }
}

/// Handle PATCH users route and let users modifie their profile
pub fn patch(vanity: String, body: crate::model::body::UserPatch) -> Result<WithStatus<Json>, cdrs::error::Error> {
    let res = match query("SELECT username, avatar, bio, email, password FROM accounts.users WHERE vanity = ?", vec![vanity.clone()]) {
        Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return Ok(warp::reply::with_status(warp::reply::json(
                &Error {
                    error: true,
                    message: "Unknown user".to_string()
                }
            ), warp::http::StatusCode::NOT_FOUND));
        }
    };

    let mut is_psw_valid: bool = false;
    if body.password.is_some() {
        if crate::helpers::crypto::hash_test(std::str::from_utf8(&res[0][4].clone().into_plain().unwrap()[..]).unwrap(), body.password.unwrap().as_ref()) {
            is_psw_valid = true;
        } else {
            return Ok(super::err("Invalid password".to_string()));
        }
    }

    let mut username = std::str::from_utf8(&res[0][0].clone().into_plain().unwrap()[..]).unwrap().to_string();
    let mut email = std::str::from_utf8(&res[0][3].clone().into_plain().unwrap()[..]).unwrap().to_string();
    let mut bio: Option<String> = None;
    let mut birthdate: Option<String> = None;
    let phone: Option<String> = None;

    // Change username
    if body.username.is_some() {
        let nusername = match body.username {
            Some(u) => u,
            None => "".to_string()
        };
    
        if nusername.len() >= 16 {
            return Ok(super::err("Invalid username".to_string()));
        } else {
            username = nusername;
        }
    }
    
    // Change bio
    if body.bio.is_some() {
        let nbio = match body.bio {
            Some(b) => b,
            None => "".to_string()
        };
    
        if nbio.len() > 160 {
            return Ok(super::err("Invalid bio".to_string()));
        } else if nbio.is_empty() {
            bio = None
        } else {
            bio = Some(nbio);
        }
    }

    // Change email
    if body.email.is_some() {
        let nemail = match body.email {
            Some(e) => e,
            None => "".to_string()
        };
    
        if !is_psw_valid || !EMAIL.is_match(&nemail) {
            return Ok(super::err("Invalid email".to_string()));
        } else {
            let mut hasher = Keccak256::new();
            hasher.update(nemail.as_bytes());
            email = hex::encode(&hasher.finalize()[..]);
        }
    }
    
    // Change birthdate
    if body.birthdate.is_some() {
        let birth = match body.birthdate {
            Some(b) => b,
            None => "".to_string()
        };
    
        if !BIRTH.is_match(&birth) {
            return Ok(super::err("Invalid birthdate".to_string()));
        } else {
            let dates: Vec<&str> = birth.split('-').collect();
    
            if 13 > crate::helpers::get_age(dates[0].parse::<i32>().unwrap(), dates[1].parse::<u32>().unwrap(), dates[2].parse::<u32>().unwrap()) as i32 {
                suspend(vanity)?;
                return Ok(super::err("Your account has been suspended: age".to_string()));
            } else {
                birthdate = Some(encrypt(birth.as_bytes()));
            }
        }
    }
    
    // Change phone
    if body.phone.is_some() {
        let _phone = match body.phone {
            Some(p) => p,
            None => "".to_string()
        };
            
        return Ok(super::err("Phones not implemented yet".to_string()));
    }

    // Change 2FA (mfa)
    if body.mfa.is_some() {
        let nmfa = match body.mfa {
            Some(b) => b,
            None => "".to_string()
        };

        match query("UPDATE accounts.users SET mfa_code = ? WHERE vanity = ?", vec![encrypt(nmfa.as_bytes()), vanity.clone()]) {
            Ok(_) => {},
            Err(_) => {
                return Ok(super::err("Internal server error".to_string()));
            }
        };
    }
    
    // Change password
    if body.newpassword.is_some() {
        let psw = match body.newpassword {
            Some(p) => p,
            None => "".to_string()
        };
        
        if !is_psw_valid || !PASSWORD.is_match(&psw) {
            return Ok(super::err("Invalid password".to_string()));
        } else {
            match query("UPDATE accounts.users SET password = ? WHERE vanity = ?", vec![hash(psw.as_ref()), vanity.clone()]) {
                Ok(_) => {},
                Err(_) => {
                    return Ok(super::err("Internal server error".to_string()));
                }
            };
        }
    }

    match update_user(username, None, bio, birthdate, phone, email, vanity.clone()) {
        Ok(_) => {
            let _ = del(vanity);
            Ok(warp::reply::with_status(warp::reply::json(
                &Error {
                    error: false,
                    message: "OK".to_string()
                }
            ), warp::http::StatusCode::OK))
        },
        Err(_) => {
            Ok(super::err("Internal server error".to_string()))
        }
    }
}

/// Delete route for remove account from database
pub async fn delete(vanity: String, body: crate::model::body::Gdrp) -> Result<WithStatus<Json>> {
    let res = match query("SELECT password FROM accounts.users WHERE vanity = ?", vec![vanity.clone()]) {
        Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
        Err(_) => {
            return Ok(warp::reply::with_status(warp::reply::json(
                &Error {
                    error: true,
                    message: "Unknown user".to_string()
                }
            ), warp::http::StatusCode::NOT_FOUND));
        }
    };

    // Check if security token is valid
    match mem_get(body.security_token)? {
        Some(r) => {
            if r != "security" {
                return Ok(super::err("Invalid security_token".to_string()));
            }
        },
        None => {
            return Ok(super::err("Invalid security_token".to_string()));
        }
    };

    if !crate::helpers::crypto::hash_test(std::str::from_utf8(&res[0][0].clone().into_plain().unwrap()[..]).unwrap(), body.password.as_ref()) {
        return Ok(super::err("Invalid password".to_string()));
    }

    for url in dotenv::var("SERVICES").expect("Missing env `SERVICES`").split(' ').collect::<Vec<&str>>().iter().map(|&s| s.to_owned()) {
        let _ = delete_account(url).await;
    }

    query(format!("UPDATE accounts.users SET deleted = {}, expire_at = '{}' WHERE vanity = ?", true, (chrono::Utc::now()+chrono::Duration::days(30)).format("%Y-%m-%d+0000")), vec![vanity])?;

    Ok(warp::reply::with_status(warp::reply::json(
        &Error {
            error: false,
            message: "OK".to_string()
        }
    ), warp::http::StatusCode::OK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex() {
        assert!(EMAIL.is_match("foo@🏹.to"));
        assert!(PASSWORD.is_match("Test1234_"));
        assert!(BIRTH.is_match("2000-01-01"));
    }
}