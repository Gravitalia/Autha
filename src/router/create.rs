use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::database::Database;
use super::ValidatedForm;

#[derive(Debug, Deserialize, Validate)]
pub struct Body {
    #[validate(length(min = 2, max = 15))]
    vanity: String,
    #[validate(email(message = "Email must be formated."))]
    email: String,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: String,
}

#[derive(Debug, Serialize)]
pub struct Response {
    vanity: String,
    token: String,
    locale: String,
}

pub async fn create(
    State(_db): State<Database>,
    ValidatedForm(_body): ValidatedForm<Body>,
) -> Json<Response> {
    Json(Response {
        vanity: String::default(),
        token: String::default(),
        locale: String::default(),
    })
}
