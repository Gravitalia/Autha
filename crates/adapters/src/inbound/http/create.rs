//! Account creation HTTP handler.

use application::dto::CreateAccountRequestDto;
use application::ports::inbound::CreateAccount;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use domain::auth::password::Password;
use domain::identity::email::EmailAddress;
use domain::identity::id::UserId;
use serde::{Deserialize, Serialize};
use validator::Validate;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

#[derive(Debug, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct CreateAccountResponse {
    pub token_type: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Create a new user account.
pub async fn create_account_handler<S>(
    State(service): State<S>,
    Valid(request): Valid<CreateAccountRequest>,
) -> Result<(StatusCode, Json<CreateAccountResponse>), HttpError>
where
    S: CreateAccount,
{
    let dto = CreateAccountRequestDto {
        user_id: UserId::parse(request.id.to_lowercase())?,
        email: EmailAddress::parse(&request.email)?,
        password: Password::new(request.password)?,
        locale: request.locale,
        invite_code: request.invite,
        ip_address: None,
    };

    let response = service.execute(dto).await.into_http_result()?;

    Ok((
        StatusCode::CREATED,
        Json(CreateAccountResponse {
            token_type: response.token_type,
            token: response.access_token,
            refresh_token: response.refresh_token,
            expires_in: response.expires_in,
        }),
    ))
}
