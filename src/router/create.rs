use warp::reply::{WithStatus, Json};
use regex::Regex;

/// Handle create route and check if everything is valid
pub async fn create(body: crate::model::Body::Create) -> Result<WithStatus<Json>, memcache::MemcacheError> {
    // Email verification
    if !Regex::new(r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,7})$").unwrap().is_match(&body.email) {
        return Ok(super::err("Invalid email".to_string()));
    }
    // Password checking [Security]
    if !Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap().is_match(&body.password) {
        return Ok(super::err("Invalid password".to_string()));
    }
    // Vanity verification
    if !Regex::new(r"[A-z|0-9|_]{3,16}").unwrap().is_match(&body.vanity) {
        return Ok(super::err("Invalid vanity".to_string()));
    }
    // Username checking
    if body.username.len() >= 16 {
        return Ok(super::err("Invalid username".to_string()));
    }
    
    Ok(super::err("In development".to_string()))
}