//! PostgreSQL implementation of RefreshTokenRepository.

use application::error::{ApplicationError, Result, ToInternal};
use application::ports::outbound::RefreshTokenRepository;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use domain::identity::id::UserId;
use sqlx::PgPool;

/// PostgreSQL refresh token repository.
pub struct PgRefreshTokenRepository {
    pool: PgPool,
    token_ttl_days: i64,
}

impl PgRefreshTokenRepository {
    /// Create a new [`PgRefreshTokenRepository`].
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            token_ttl_days: 15,
        }
    }

    /// Update token time-to-live (TTL).
    pub fn with_ttl_days(mut self, days: i64) -> Self {
        self.token_ttl_days = days;
        self
    }
}

#[async_trait]
impl RefreshTokenRepository for PgRefreshTokenRepository {
    async fn store(
        &self,
        token: &str,
        user_id: &UserId,
        ip_address: Option<&String>,
    ) -> Result<()> {
        let now = Utc::now();
        let expires_at = now + Duration::days(self.token_ttl_days);

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (token, user_id, ip_address, created_at, expires_at, revoked)
            VALUES ($1, $2, $3, $4, $5, false)
            "#,
        )
        .bind(token)
        .bind(user_id.as_str())
        .bind(ip_address)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .catch()?;

        Ok(())
    }

    async fn find_user_id(&self, token: &str) -> Result<Option<UserId>> {
        let record = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT user_id
            FROM refresh_tokens
            WHERE token = $1
              AND revoked = false
              AND expires_at > NOW()
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .catch()?;

        match record {
            Some(id) => Ok(UserId::parse(id.0).ok()),
            _ => Ok(None),
        }
    }

    async fn revoke(&self, token: &str) -> Result<()> {
        let result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked = true
            WHERE token = $1
            "#,
        )
        .bind(token)
        .execute(&self.pool)
        .await
        .catch()?;

        if result.rows_affected() == 0 {
            return Err(ApplicationError::UserNotFound);
        }

        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: &UserId) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked = true
            WHERE user_id = $1 AND revoked = false
            "#,
        )
        .bind(user_id.as_str())
        .execute(&self.pool)
        .await
        .catch()?;

        Ok(())
    }
}
