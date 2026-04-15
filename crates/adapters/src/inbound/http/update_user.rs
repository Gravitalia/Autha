//! Update user HTTP handler.

use std::sync::Arc;

use application::dto::UpdateUserDto;
use application::ports::inbound::UpdateUser;
use axum::extract::State;
use axum::{Extension, Json};
use domain::identity::id::UserId;

/// Handler for `PATCH /users/@me`
pub async fn handler(
    State(service): State<Arc<dyn UpdateUser>>,
    Extension(user_id): Extension<UserId>,
    Json(payload): Json<UpdateUserDto>,
) -> Result<Json<Vec<String>>, axum::http::StatusCode> {
    match service.update(&user_id, payload).await {
        Ok(keys) => Ok(Json(keys)),
        Err(err) => {
            tracing::error!(%err, "failed to update user");
            Err(axum::http::StatusCode::BAD_REQUEST)
        },
    }
}
