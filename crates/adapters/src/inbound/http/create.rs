//! Account creation HTTP handler.

use std::sync::Arc;

use application::dto::{AuthResponseDto, CreateAccountRequestDto};
use application::ports::inbound::CreateAccount;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use domain::auth::password::Password;
use domain::identity::email::EmailAddress;
use domain::identity::id::UserId;
use serde::Deserialize;
use validator::Validate;

use crate::inbound::http::errors::{HttpError, IntoHttpResult};
use crate::inbound::http::extractor::Valid;
use crate::inbound::http::validation::{
    validate_locale, validate_password_strength, validate_user_id,
};

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountRequest {
    #[validate(custom(function = "validate_user_id"))]
    pub id: String,
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(
        length(min = 8, max = 255),
        custom(function = "validate_password_strength")
    )]
    pub password: String,
    #[validate(custom(function = "validate_locale"))]
    pub locale: Option<String>,
    pub invite: Option<String>,
}

/// Create a new user account.
pub async fn create_account_handler(
    State(service): State<Arc<dyn CreateAccount>>,
    Valid(request): Valid<CreateAccountRequest>,
) -> Result<(StatusCode, Json<AuthResponseDto>), HttpError> {
    let dto = CreateAccountRequestDto {
        user_id: UserId::parse(request.id.to_lowercase())?,
        email: EmailAddress::parse(&request.email)?,
        password: Password::new(request.password)?,
        locale: request.locale,
        invite_code: request.invite,
        ip_address: None,
    };

    let response = service.execute(dto).await.into_http_result()?;

    Ok((StatusCode::CREATED, Json(response)))
}
