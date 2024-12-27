//! Public configuration page for front-end identification and customization.

use axum::{extract::State, Json};

use crate::status::Configuration;

/// Public server status (configuration).
pub async fn status(State(configuration): State<Configuration>) -> Json<Configuration> {
    Json(configuration)
}
