mod model;
use regex::Regex;
use warp::reply::{WithStatus, Json};

fn err(message: String) -> WithStatus<Json> {
    warp::reply::with_status(warp::reply::json(
        &model::Error{
            error: true,
            message,
        }
    ),
    warp::http::StatusCode::BAD_REQUEST)
}

pub fn create(body: model::Create, _finger: String) -> WithStatus<Json> {
    // Email verification
    if !Regex::new(r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,7})$").unwrap().is_match(&body.email) {
        return err("Invalid email".to_string());
    }
    // Password checking [Security]
    if !Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap().is_match(&body.password) {
        return err("Invalid password".to_string());
    }
    // Vanity verification
    if !Regex::new(r"[A-z|0-9|_]{3,16}").unwrap().is_match(&body.vanity) {
        return err("Invalid vanity".to_string());
    }
    // Username checking
    if body.username.len() >= 16 {
		return err("Invalid username".to_string());
	}
    // Phone verification
    let mut phone: String = "".to_string();
    if body.phone.is_some() {
        if !Regex::new(r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$").unwrap().is_match(body.phone.as_ref().unwrap()) {
            return err("Invalid phone".to_string());
        } else {
            phone = super::helpers::encrypt(body.phone.unwrap().as_bytes())
        }
    }
    // Birthdate verification
    let mut birth: String = "".to_string();
    if body.birthdate.is_some() {
        if !Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap().is_match(body.birthdate.as_ref().unwrap()) {
            return err("Invalid birthdate".to_string());
        } else {
            birth = super::helpers::encrypt(body.birthdate.unwrap().as_bytes())
        }
    }

    warp::reply::with_status(warp::reply::json(
        &model::CreateResponse{
            token: phone,
            vanity: super::helpers::hash("test".as_bytes())
        }
    ),
    warp::http::StatusCode::CREATED)
}