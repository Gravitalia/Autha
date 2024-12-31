use sqlx::PgPool;

#[derive(Clone)]
pub struct Database {
    postgres: PgPool,
}

impl Database {
    pub async fn new(pg_url: &str) -> Result<Self, sqlx::Error> {
        let postgres = PgPool::connect(pg_url).await?;

        Ok(Self { postgres })
    }
}
