//! PostgreSQL implementation for account repository.

use application::dto::AccountDto;
use application::error::{ApplicationError, Result, ToInternal};
use application::ports::outbound::AccountRepository;
use async_trait::async_trait;
use chrono::Utc;
use domain::auth::email::EmailHash;
use domain::error::DomainError;
use domain::identity::id::UserId;
use sqlx::PgPool;
use sqlx::postgres::PgQueryResult;

use super::models::UserRecord;

/// Base SQL for selecting a user and aggregating their public keys.
const USER_SELECT_BASE: &str = r#"
    SELECT
        u.id,
        u.username,
        u.email_hash,
        u.email_cipher,
        u.totp_secret,
        u.locale,
        u.summary,
        u.avatar,
        u.flags,
        u.password,
        u.created_at,
        u.deleted_at,
        COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'id', k.id::text,
                    'owner', k.user_id,
                    'public_key_pem', k.pem,
                    'created_at', k.created_at
                )
            ) FILTER (WHERE k.id IS NOT NULL),
            '[]'::jsonb
        ) AS public_keys
    FROM users u
    LEFT JOIN keys k ON k.user_id = u.id
"#;

/// PostgreSQL account repository.
pub struct PgAccountRepository {
    pool: PgPool,
}

impl PgAccountRepository {
    /// Create a new [`PgAccountRepository`].
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Helper to execute the user query with a custom filter.
    async fn find_one_by_filter(
        &self,
        filter_sql: &str,
        bind_val: &str,
    ) -> Result<Option<AccountDto>> {
        let query_sql = format!(
            "{} WHERE {} AND u.deleted_at IS NULL GROUP BY u.id",
            USER_SELECT_BASE, filter_sql
        );

        let record = sqlx::query_as::<_, UserRecord>(&query_sql)
            .bind(bind_val)
            .fetch_optional(&self.pool)
            .await
            .catch()?;

        match record {
            Some(record) => Ok(Some(record.try_into_dto().catch()?)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl AccountRepository for PgAccountRepository {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<AccountDto>> {
        self.find_one_by_filter("u.id = $1", id.as_str()).await
    }

    async fn find_by_email_hash(
        &self,
        email_hash: &EmailHash,
    ) -> Result<Option<AccountDto>> {
        self.find_one_by_filter("u.email_hash = $1", email_hash.as_str())
            .await
    }

    async fn create(&self, account: &AccountDto) -> Result<()> {
        let record = UserRecord::from(account);

        let result = sqlx::query(
            r#"
            INSERT INTO users (
                id, username, email_hash, email_cipher, totp_secret,
                locale, summary, avatar, flags, password,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
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
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && db_err.code() == Some("23505".into())
                {
                    let constraint = db_err.constraint().unwrap_or("");

                    if constraint.contains("pkey") || constraint.contains("id")
                    {
                        return Err(DomainError::ValidationFailed {
                            field: "id".to_string(),
                            message: "ID is already in use.".to_string(),
                        }
                        .into());
                    }

                    if constraint.contains("email") {
                        return Err(DomainError::ValidationFailed {
                            field: "email".to_string(),
                            message: "Email is already in use.".to_string(),
                        }
                        .into());
                    }
                }
                Err(ApplicationError::Internal(e.into()))
            },
        }
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
                password = $10
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
        .execute(&self.pool)
        .await
        .catch()?;

        if result.rows_affected() == 0 {
            return Err(ApplicationError::UserNotFound);
        }

        Ok(())
    }

    async fn delete(&self, id: &UserId) -> Result<()> {
        let deletion_date = Utc::now() + chrono::Duration::days(30);

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
