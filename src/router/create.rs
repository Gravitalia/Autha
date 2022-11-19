use regex::Regex;
use warp::reply::{WithStatus, Json};
use sha256::digest;
use crate::database::cassandra::query;
use crate::database::mem;

#[doc = "Creates accounts from the data provided"]
/// Example
/// ```rust
/// match router::create::create(router::model::Create { username: "CoolUser".to_string(), vanity: "cooluser".to_string(), email: "test@gravitalia.com".to_string(), password: "notapassword".to_string(), birthdate: None, phone: None } , "0088577f20968a97830a9190541e1a97f73360332d25a9d04232fd737b5cba6a".to_string()).await {
///      Ok(r) => {
///          Ok(r)
///      },
///      Err(_) => {
///          Err(warp::reject::custom(UnknownError))
///      }
///  }
/// ```
pub async fn create(body: super::model::Create, finger: String) -> Result<WithStatus<Json>, memcache::MemcacheError> {
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

    let rate_limit = match mem::get(digest(&*body.email))? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 1 {
        return Ok(warp::reply::with_status(warp::reply::json(
            &super::model::Error{
                error: true,
                message: "You can only create an account in 5 minutes".to_string()
            }
        ),
        warp::http::StatusCode::TOO_MANY_REQUESTS));
    }

    if !query("SELECT vanity FROM accounts.users WHERE email = ?", vec![digest(&*body.email)]).await.rows.unwrap().is_empty() {
        Ok(super::err("Invalid email".to_string()))
    } else if !query("SELECT vanity FROM accounts.users WHERE vanity = ?", vec![body.vanity.clone()]).await.rows.unwrap().is_empty() {
        Ok(super::err("Invalid vanity".to_string()))
    } else {
        // Phone verification
        let mut phone: Option<String> = None;
        if body.phone.is_some() {
            if !Regex::new(r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$").unwrap().is_match(body.phone.as_ref().unwrap()) {
                return Ok(super::err("Invalid phone".to_string()));
            } else {
                phone = Some(crate::helpers::encrypt(body.phone.unwrap().as_bytes()));
            }
        }
        // Birthdate verification
        let mut birth: Option<String> = None;
        if body.birthdate.is_some() {
            if !Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap().is_match(body.birthdate.as_ref().unwrap()) {
                return Ok(super::err("Invalid birthdate".to_string()));
            } else {
                birth = Some(crate::helpers::encrypt(body.birthdate.unwrap().as_bytes()));
            }
        }

        //let _ = mem::set(digest(&*body.email), mem::SetValue::Number(rate_limit+1));
        crate::database::cassandra::create_user(&body.vanity.to_lowercase(), digest(body.email), body.username, crate::helpers::hash(body.password.as_ref()), phone, birth).await;

        Ok(warp::reply::with_status(warp::reply::json(
            &super::model::CreateResponse{
                token: crate::helpers::create_jwt(body.vanity.to_lowercase(), Some(digest(&*finger)), Some(crate::database::cassandra::create_security(body.vanity.to_lowercase(), crate::router::model::SecurityCode::Jwt as u8, finger, None, None).await.to_string())).await
            }
        ),
        warp::http::StatusCode::CREATED))
    }
}