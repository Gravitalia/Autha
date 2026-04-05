//! Get user HTTP handler.

use std::sync::Arc;

use application::ports::inbound::GetUser;
use axum::Json;
use axum::extract::{Path, State};
use domain::identity::id::UserId;

use crate::inbound::http::errors::{HttpError, IntoHttpResult};

/// Gets a user.
pub async fn get_user_handler(
    State(service): State<Arc<dyn GetUser>>,
    Path(id): Path<String>,
) -> Result<Json<application::dto::UserResponseDto>, HttpError> {
    let response = service
        .execute(UserId::parse(id)?)
        .await
        .into_http_result()?;

    Ok(Json(response))
}
