//! Public configuration page for front-end identification and customization.

use axum::{extract::State, Json};

use crate::status::Configuration;

/// Public server status (configuration).
pub async fn status(State(configuration): State<Configuration>) -> Json<Configuration> {
    Json(configuration)
}

#[cfg(test)]
mod tests {
    use crate::*;
    use axum::{
        body::Body as RequestBody,
        http::{self, Request, StatusCode},
    };
    use sqlx::{Pool, Postgres};
    use tower::ServiceExt;

    #[sqlx::test]
    async fn test_status_handler(pool: Pool<Postgres>) {
        // State pool is useless, but required.
        let state = AppState {
            db: database::Database { postgres: pool },
            config: status::Configuration::default(),
        };
        let app = app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/status.json")
                    .body(RequestBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
