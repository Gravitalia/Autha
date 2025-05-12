//! Public configuration page for front-end identification and customization.

use axum::{Json, extract::State};

use crate::status::Configuration;

/// Public server status (configuration).
pub async fn status(State(configuration): State<Configuration>) -> Json<Configuration> {
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
        let config = status::Configuration::default();
        // State pool is useless, but required.
        let state = AppState {
            db: database::Database { postgres: pool },
            config: config.clone(),
            ldap: ldap::Ldap::default(),
        };
        let app = app(state);

        let response = make_request(app, Method::GET, "/status.json", String::default()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: status::Configuration = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, config);
    }
}
