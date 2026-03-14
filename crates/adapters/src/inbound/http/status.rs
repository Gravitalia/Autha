//! JSON HTTP status handler.

use std::sync::Arc;

use application::ports::inbound::Status;
use axum::extract::State;
use axum::response::IntoResponse;

/// Instance status handler.
pub async fn status_handler(
    State(service): State<Arc<dyn Status>>,
) -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        service.execute(),
    )
}
