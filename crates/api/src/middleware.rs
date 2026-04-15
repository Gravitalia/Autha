//! API middlewares.

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use domain::identity::id::UserId;

use crate::state::AppState;

const BEARER: &str = "Bearer ";

/// Middleware to extract and verify the JWT authorization token.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with(BEARER) => {
            header.replace(BEARER, "")
        },
        _ => {
            return Err((StatusCode::UNAUTHORIZED, "Missing or invalid token")
                .into_response());
        },
    };

    let claims = state.token.signer().verify_token(&token).map_err(|_| {
        (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response()
    })?;

    let user_id = UserId::parse(&claims.sub).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid user ID in token",
        )
            .into_response()
    })?;

    req.extensions_mut().insert(user_id);

    Ok(next.run(req).await)
}
