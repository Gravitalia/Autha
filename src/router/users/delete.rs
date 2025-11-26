//! Delete user from database with 30-day retention.

use axum::Extension;
use axum::extract::State;
use serde::Deserialize;

use crate::router::Valid;
use crate::user::UserService;
use crate::{AppState, ServerError};

#[derive(Debug, validator::Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteBody {
    totp_code: Option<String>,
    #[validate(length(
        min = 8,
        message = "Password must contain at least 8 characters."
    ))]
    password: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<UserService>,
    Valid(body): Valid<DeleteBody>,
) -> Result<(), ServerError> {
    state
        .crypto
        .pwd
        .verify_password(&body.password, &user.data.password)?;
    state
        .crypto
        .symmetric
        .check_totp(body.totp_code, &user.data.totp_secret)?;

    user.delete().await?;
    Ok(())
}
