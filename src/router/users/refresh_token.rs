//! Get a new token with refresh token.

use axum::Json;
use axum::extract::State;
use serde::Deserialize;
use validator::{Validate, ValidationError, ValidationErrors};

use crate::router::Valid;
use crate::router::create::{Response, TOKEN_TYPE};
use crate::user::UserBuilder;
use crate::{AppState, ServerError};

fn validate_grant_type(grant_type: &str) -> Result<(), ValidationError> {
    // As specified on OAuth2.0 spec, reject if grant_type is not valid.
    if grant_type != "refresh_token" {
        return Err(ValidationError::new("invalid_grant_type"));
    }

    Ok(())
}

fn invalid_refresh_token() -> ValidationErrors {
    let mut errors = ValidationErrors::new();
    errors.add(
        "refresh_token",
        ValidationError::new("refresh_token")
            .with_message("Invalid refresh token.".into()),
    );
    errors
}

#[derive(Debug, Validate, Deserialize)]
pub struct Body {
    #[validate(length(equal = crate::user::TOKEN_LENGTH))]
    refresh_token: String,
    #[validate(custom(
        function = "validate_grant_type",
        message = "\"grant_type\" must be \"refresh_token\"."
    ))]
    grant_type: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>, ServerError> {
    let mut tx = state.db.postgres.begin().await?;

    let data = sqlx::query!(
        "SELECT user_id, expire_at, ip FROM tokens WHERE token = $1",
        body.refresh_token
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| invalid_refresh_token())?;

    if data.expire_at <= chrono::Utc::now() {
        return Err(invalid_refresh_token().into());
    }

    let user = UserBuilder::new()
        .id(data.user_id.to_lowercase())
        .ip(data.ip)
        .build(state.db.postgres.clone(), state.crypto)
        .find_by_id()
        .await?;

    let refresh_token = user.generate_token().await?;
    let token = state.token.create(&user.data.id)?;

    sqlx::query!("DELETE FROM tokens WHERE token = $1", body.refresh_token)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Json(Response {
        token_type: TOKEN_TYPE.to_owned(),
        token,
        refresh_token,
        expires_in: crate::token::EXPIRATION_TIME,
    }))
}
