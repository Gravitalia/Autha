//! PostgreSQL connection pool factory.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Default maximum number of connections in the pool.
pub const DEFAULT_POOL_SIZE: u32 = 10;

/// Create a PostgreSQL connection pool.
pub async fn create_pool(
    url: &str,
    max_connections: u32,
) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await?;

    tracing::info!(?max_connections, "postgres pool created");

    Ok(pool)
}

pub async fn migrate(db_pool: PgPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!().run(&db_pool).await?;
    Ok(())
}
