//! Get a new token with refresh token.

use axum::Json;
use axum::extract::State;
use serde::Deserialize;
use validator::ValidationError;

use crate::router::Valid;
use crate::router::create::Response;
use crate::user::User;
use crate::{AppState, ServerError};

fn validate_grant_type(grant_type: &str) -> Result<(), ValidationError> {
    // As specified on OAuth2.0 spec, reject if grant_type is not valid.
    if grant_type != "refresh_token" {
        return Err(ValidationError::new("invalid_grant_type")
            .with_message("\"grant_type\" must be \"refresh_token\".".into()));
    }

    Ok(())
}

#[derive(Debug, validator::Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    #[validate(length(equal = crate::user::TOKEN_LENGTH))]
    refresh_token: String,
    #[validate(custom(function = "validate_grant_type"))]
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
    .map_err(|_| ServerError::Unauthorized)?;

    if data.expire_at <= chrono::Utc::now() {
        return Err(ServerError::Unauthorized);
    }

    let user = User::builder()
        .with_id(data.user_id.to_lowercase())
        .with_ip(data.ip)
        .get(&state.db.postgres)
        .await?;
    let refresh_token = user.generate_token(&state.db.postgres).await?;
    let token = state.token.create(&user.id)?;

    sqlx::query!("DELETE FROM tokens WHERE token = $1", body.refresh_token)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Json(Response {
        user,
        token,
        refresh_token,
    }))
}
