use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::database::Database;

#[derive(Deserialize, Debug)]
pub struct Body {
    vanity: String,
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct Response {
    vanity: String,
    token: String,
    locale: String,
}

pub async fn create(State(db): State<Database>, Json(body): Json<Body>) -> Json<Response> {
    Json(Response {
        vanity: String::default(),
        token: String::default(),
        locale: String::default(),
    })
}
