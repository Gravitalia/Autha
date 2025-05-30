//! Get and update user data.

use axum::extract::State;
use axum::Extension;
use serde::Deserialize;

use crate::router::login::check_password;
use crate::router::Valid;
use crate::user::User;
use crate::{AppState, ServerError};

#[derive(Debug, validator::Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteBody {
    totp_code: Option<String>,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Valid(body): Valid<DeleteBody>,
) -> Result<(), ServerError> {
    check_password(&body.password, &user.password)?;
    state.crypto.check_totp(body.totp_code, &user.totp_secret)?;

    user.delete(&state.db.postgres).await?;
    Ok(())
}
