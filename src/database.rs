//! database (db) union structure.
use axum::extract::FromRef;
use sqlx::PgPool;

use crate::AppState;

pub const DEFAULT_PG_URL: &str = "postgres://postgres:postgres@localhost:5432/autha";

/// Custom db structure to pass to Axum.
#[derive(Clone)]
pub struct Database {
    pub postgres: PgPool,
}

impl Database {
    /// Init database connections.
    pub async fn new(pg_url: &str) -> Result<Self, sqlx::Error> {
        let postgres = PgPool::connect(pg_url).await?;

        Ok(Self { postgres })
    }
}

impl FromRef<AppState> for Database {
    fn from_ref(app_state: &AppState) -> Database {
        app_state.db.clone()
    }
}
