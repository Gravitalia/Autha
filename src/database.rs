//! database (db) union structure.
use axum::extract::FromRef;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::AppState;

pub const DEFAULT_CREDENTIALS: &str = "postgres";
pub const DEFAULT_DATABASE_NAME: &str = "autha";
pub const DEFAULT_POOL_SIZE: u32 = 10;

/// Custom db structure to pass to Axum.
#[derive(Clone)]
pub struct Database {
    pub postgres: PgPool,
}

impl Database {
    /// Init database connections.
    pub async fn new(
        hostname: &str,
        username: &str,
        password: &str,
        db: &str,
        pool: u32,
    ) -> Result<Self, sqlx::Error> {
        let addr = format!("postgres://{username}:{password}@{hostname}/{db}");
        let pool = PgPoolOptions::new().max_connections(pool);
        let postgres = pool.connect(&addr).await?;

        tracing::info!(%hostname, %db, "postgres connected");

        Ok(Self { postgres })
    }
}

impl FromRef<AppState> for Database {
    fn from_ref(app_state: &AppState) -> Database {
        app_state.db.clone()
    }
}
