//! Public configuration page for front-end identification and customization.

use std::env::var;

use axum::Json;
use serde::Serialize;

/// Structured configuration.
#[derive(Serialize)]
pub struct Status {
    version: String,
    name: String,
    favicon: Option<String>,
}

/// Public server status (configuration).
pub async fn status() -> Json<Status> {
    Json(Status {
        version: env!("CARGO_PKG_VERSION").into(),
        name: if let Ok(name) = var("SERVER_NAME") {
            name
        } else {
            env!("CARGO_CRATE_NAME").into()
        },
        favicon: if let Ok(path) = var("SERVER_ICON") {
            Some(path)
        } else {
            None
        },
    })
}
