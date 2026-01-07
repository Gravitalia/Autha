//! Users-related HTTP API.
mod delete;
mod get;
pub mod refresh_token;
mod update;

use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::header;
use axum::response::Response;
use axum::routing::{delete, get, patch};
use axum::{Router, middleware};

use crate::user::{UserBuilder, UserService};
use crate::{AppState, ServerError};

const BEARER: &str = "Bearer ";
const ME_ROUTE: &str = "@me";

/// Custom middleware for authentification.
async fn auth(
    State(state): State<AppState>,
    user_id: Option<Path<String>>,
    mut req: Request,
    next: middleware::Next,
) -> Result<Response, ServerError> {
    let user_id = match user_id {
        Some(user_id) => user_id.to_string(),
        None => ME_ROUTE.to_string(),
    };
    let user_id = if user_id == ME_ROUTE {
        match req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
        {
            Some(token) => {
                let token = token.replace(BEARER, "");
                match state.token.decode(&token) {
                    Ok(claims) => claims.sub,
                    Err(_) => return Err(ServerError::Unauthorized),
                }
            },
            None => return Err(ServerError::Unauthorized),
        }
    } else {
        user_id
    };

    let user = UserBuilder::new()
        .id(&user_id)
        .build(state.db.postgres.clone(), Arc::clone(&state.crypto))
        .find_by_id()
        .await?;

    req.extensions_mut().insert::<UserService>(user);
    Ok(next.run(req).await)
}

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        // `GET /users/:ID` goes to `get`.
        .route("/{user_id}", get(get::handler))
        .route("/@me", get(get::handler))
        // `PATCH /users/@me` goes to `patch`. Authorization required.
        .route("/@me", patch(update::handler))
        // `DELETE /users/@me` goes to `delete`. Authorization required.
        .route("/@me", delete(delete::handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
}
