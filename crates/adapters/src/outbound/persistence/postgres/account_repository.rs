//! PostgreSQL implementation for account repository.

use application::dto::AccountDto;
use application::error::{ApplicationError, Result, ToInternal};
use application::ports::outbound::AccountRepository;
use async_trait::async_trait;
use chrono::Utc;
use domain::auth::email::EmailHash;
use domain::identity::id::UserId;
use sqlx::PgPool;
use sqlx::postgres::PgQueryResult;

use super::models::UserRecord;

/// PostgreSQL account repository.
pub struct PgAccountRepository {
    pool: PgPool,
}

impl PgAccountRepository {
    /// Create a new [`PgAccountRepository`].
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccountRepository for PgAccountRepository {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<AccountDto>> {
        let record = sqlx::query_as::<_, UserRecord>(
            r#"
            SELECT 
                id, username, email_hash, email_cipher, totp_secret,
                locale, summary, avatar, flags, password,
                created_at, deleted_at, public_keys
            FROM users
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .catch()?;

        match record {
            Some(record) => Ok(Some(record.try_into_dto().catch()?)),
            _ => Ok(None),
        }
    }

    async fn find_by_email_hash(
        &self,
        email_hash: &EmailHash,
    ) -> Result<Option<AccountDto>> {
        let record = sqlx::query_as::<_, UserRecord>(
            r#"
            SELECT 
                id, username, email_hash, email_cipher, totp_secret,
                locale, summary, avatar, flags, password,
                created_at, deleted_at, public_keys
            FROM users
            WHERE email_hash = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(email_hash.as_str())
        .fetch_optional(&self.pool)
        .await
        .catch()?;

        match record {
            Some(record) => Ok(Some(record.try_into_dto().catch()?)),
            _ => Ok(None),
        }
    }

    async fn create(&self, account: &AccountDto) -> Result<()> {
        let record = UserRecord::from(account);

        sqlx::query(
            r#"
            INSERT INTO users (
                id, username, email_hash, email_cipher, totp_secret,
                locale, summary, avatar, flags, password,
                created_at, public_keys
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(&record.id)
        .bind(&record.username)
        .bind(&record.email_hash)
        .bind(&record.email_cipher)
        .bind(&record.totp_secret)
        .bind(&record.locale)
        .bind(&record.summary)
        .bind(&record.avatar)
        .bind(record.flags)
        .bind(&record.password)
        .bind(record.created_at)
        .bind(sqlx::types::Json(&record.public_keys))
        .execute(&self.pool)
        .await
        .catch()?;

        Ok(())
    }

    async fn update(&self, account: &AccountDto) -> Result<()> {
        let record = UserRecord::from(account);

        let result: PgQueryResult = sqlx::query(
            r#"
            UPDATE users
            SET 
                username = $2,
                email_hash = $3,
                email_cipher = $4,
                totp_secret = $5,
                locale = $6,
                summary = $7,
                avatar = $8,
                flags = $9,
                password = $10,
                public_keys = $11
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(&record.id)
        .bind(&record.username)
        .bind(&record.email_hash)
        .bind(&record.email_cipher)
        .bind(&record.totp_secret)
        .bind(&record.locale)
        .bind(&record.summary)
        .bind(&record.avatar)
        .bind(record.flags)
        .bind(&record.password)
        .bind(sqlx::types::Json(&record.public_keys))
        .execute(&self.pool)
        .await
        .catch()?;

        if result.rows_affected() == 0 {
            return Err(ApplicationError::UserNotFound);
        }

        Ok(())
    }

    async fn delete(&self, id: &UserId) -> Result<()> {
        let deletion_date =
            Utc::now().date_naive() + chrono::Duration::days(30);

        let result: PgQueryResult = sqlx::query(
            r#"
            UPDATE users
            SET deleted_at = $2
            WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(id.as_str())
        .bind(deletion_date)
        .execute(&self.pool)
        .await
        .catch()?;

        if result.rows_affected() == 0 {
            return Err(ApplicationError::UserNotFound);
        }

        Ok(())
    }
}
