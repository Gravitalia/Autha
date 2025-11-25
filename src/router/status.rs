//! Public configuration page for front-end identification and customization.

use axum::{Json, extract::State};

use std::sync::Arc;

use crate::config::Configuration;

/// Public server status (configuration).
pub async fn status(
    State(configuration): State<Arc<Configuration>>,
) -> Json<Arc<Configuration>> {
    Json(configuration)
}

#[cfg(test)]
mod tests {
    use crate::*;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use sqlx::{Pool, Postgres};

    #[sqlx::test]
    async fn test_status_handler(pool: Pool<Postgres>) {
        // State pool is useless, but required.
        let state = router::state(pool);
        let config = state.config.clone();
        let app = app(state);

        let response =
            make_request(app, Method::GET, "/status.json", String::default())
                .await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: config::Configuration =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(serde_json::json!(body), serde_json::json!(config));
    }
}
