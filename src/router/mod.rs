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

    if body.phone.is_some() {
        if !Regex::new(r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$").unwrap().is_match(&body.phone.unwrap()) {
            return err("Invalid phone".to_string());
        }
    }

    warp::reply::with_status(warp::reply::json(
        &model::CreateResponse{
            token: "token".to_string(),
            vanity: "vanity".to_string()
        }
    ),
    warp::http::StatusCode::CREATED)
}