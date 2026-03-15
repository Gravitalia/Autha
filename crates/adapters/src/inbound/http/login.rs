//! Login HTTP handler.

use std::sync::Arc;

use application::dto::{AuthRequestDto, AuthResponseDto};
use application::error::ApplicationError;
use application::ports::inbound::Authenticate;
use axum::Json;
use axum::extract::State;
use domain::identity::email::EmailAddress;
use serde::Deserialize;
use validator::Validate;

use crate::inbound::http::errors::{HttpError, IntoHttpResult};
use crate::inbound::http::extractor::Valid;

/// Login request body.
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    /// User email. Mutually exclusive with `id`.
    #[validate(email(message = "Invalid email format"))]
    pub email: Option<String>,
    /// User ID. Mutually exclusive with `email`.
    #[validate(length(min = 2, max = 15))]
    pub id: Option<String>,
    /// User password.
    #[validate(length(min = 8, max = 128))]
    pub password: String,
    /// TOTP code (required if MFA is enabled).
    #[serde(rename = "totpCode")]
    pub totp_code: Option<String>,
}

/// Authenticates a user.
pub async fn login_handler(
    State(service): State<Arc<dyn Authenticate>>,
    Valid(request): Valid<LoginRequest>,
) -> Result<Json<AuthResponseDto>, HttpError> {
    let email = request
        .email
        .as_deref()
        .map(EmailAddress::parse)
        .transpose()
        .map_err(|_| HttpError::from(ApplicationError::UserNotFound))?;
    let dto = AuthRequestDto {
        email,
        user_id: request.id,
        password: request.password,
        totp_code: request.totp_code,
        ip_address: None, // TODO: extract from X-Forwarded-For.
    };

    let response = service.execute(dto).await.into_http_result()?;

    Ok(Json(response))
}
