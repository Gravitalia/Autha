//! Middlewares for routes.

use axum::extract::State;
use validator::{ValidationError, ValidationErrors};

use crate::AppState;
use crate::ServerError;
use crate::error::Result;
use crate::router::create::Body;

const BODY_LIMIT: usize = 30_000;

fn invalid_code() -> ValidationErrors {
    let mut errors = ValidationErrors::new();
    errors.add(
        "invite",
        ValidationError::new("invite")
            .with_message("Invalid invite code.".into()),
    );
    errors
}

/// Middleware to handle invite codes.
pub async fn consume_invites(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response> {
    if state.config.invite_only {
        let (parts, body) = req.into_parts();
        let body_bytes = axum::body::to_bytes(body, BODY_LIMIT)
            .await
            .map_err(|err| ServerError::ParsingForm(Box::new(err)))?;
        let body = serde_json::from_slice::<Body>(&body_bytes)
            .map_err(|err| ServerError::ParsingForm(Box::new(err)))?;

        match sqlx::query!(
                r#"SELECT used_at IS NOT NULL AS is_used FROM invite_codes WHERE code = $1"#,
                body.invite
            )
            .fetch_optional(&state.db.postgres)
            .await
            {
                Ok(Some(row)) if !row.is_used.unwrap_or(false) => (),
                Ok(Some(_)) | Ok(None) | Err(_) => return Err(invalid_code().into()),
            };

        let req = axum::extract::Request::from_parts(
            parts,
            axum::body::Body::from(body_bytes),
        );

        Ok(next.run(req).await)
    } else {
        Ok(next.run(req).await)
    }
}
