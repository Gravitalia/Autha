//! database (db) union structure.
use sqlx::PgPool;

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
