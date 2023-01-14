use warp::reply::{WithStatus, Json};
use regex::Regex;
use tokio::task;

lazy_static! {
    static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    static ref VANITY: Regex = Regex::new(r"[A-z|0-9|_]{3,16}").unwrap();
}

/// Handle create route and check if everything is valid
pub async fn create(body: crate::model::body::Create) -> Result<WithStatus<Json>, String> {
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

    Ok(super::err(crate::helpers::hash("test".as_bytes()).to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex() {
        assert!(EMAIL.is_match("foo@🏹.to"));
        assert!(PASSWORD.is_match("Test1234_"));
        assert!(VANITY.is_match("realhinome"));
    }
}