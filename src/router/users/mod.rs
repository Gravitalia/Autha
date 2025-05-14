//!
mod delete;
mod get;
mod update;

use axum::extract::{Path, Request, State};
use axum::http::header;
use axum::middleware;
use axum::response::Response;
use axum::routing::{delete, get, patch};
use axum::Router;

use crate::database::Database;
use crate::user::User;
use crate::AppState;
use crate::ServerError;

/// Custom middleware for authentification.
async fn auth(
    State(db): State<Database>,
    user_id: Option<Path<String>>,
    mut req: Request,
    next: middleware::Next,
) -> Result<Response, ServerError> {
    let user_id = match user_id {
        Some(user_id) => user_id.to_string(),
        None => "@me".to_owned(),
    };
    let user_id = if user_id == "@me" {
        match req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
        {
            Some(token) => {
                match sqlx::query!("SELECT user_id FROM tokens WHERE token = $1", token)
                    .fetch_one(&db.postgres)
                    .await
                {
                    Ok(token_data) => token_data.user_id,
                    Err(_) => return Err(ServerError::Unauthorized),
                }
            }
            None => return Err(ServerError::Unauthorized),
        }
    } else {
        user_id
    };

    let user = User::default().with_id(user_id).get(&db.postgres).await?;

    req.extensions_mut().insert::<User>(user);
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
