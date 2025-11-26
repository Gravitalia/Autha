//! Handle database requests.

use sqlx::{Pool, Postgres};

use crate::error::Result;
use crate::user::User;

#[derive(Clone)]
pub struct UserRepository {
    pool: Pool<Postgres>,
}

impl UserRepository {
    /// Create a new [`UserRepository`].
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// Insert [`User`] into database.
    pub async fn insert(&self, user: &User) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let id = user.id.to_lowercase();

        sqlx::query!(
            r#"INSERT INTO users (id, username, locale, email_hash, email_cipher, password)
                VALUES ($1, $2, $3, $4, $5, $6)"#,
            id,
            user.id,
            user.locale,
            user.email_hash,
            user.email_cipher,
            user.password,
        )
        .execute(&mut *tx)
        .await?;

        if let Some(invite) = user.invite.as_ref().filter(|s| !s.is_empty()) {
            let result = sqlx::query!(
                r#"UPDATE invite_codes SET used_by = $1, used_at = NOW() WHERE code = $2 AND used_by IS NULL"#,
                id,
                invite,
            ).execute(&mut *tx)
            .await?;
            if result.rows_affected() != 1 {
                tx.rollback().await?;
                return Err(crate::middleware::invalid_code().into());
            }
        }

        tx.commit().await?;

        Ok(())
    }

    /// Find current user using `id` field.
    pub async fn find_by_id(&self, user_id: &str) -> Result<User> {
        let query = get_by_field_query(Field::Id);

        let user = sqlx::query_as::<_, User>(&query)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;

        if let Some(date) = user.deleted_at {
            return Err(crate::error::ServerError::UserDeleted { date });
        };

        Ok(user)
    }

    /// Find current user using `email` field.
    pub async fn find_by_email(&self, email_hash: &str) -> Result<User> {
        let query = get_by_field_query(Field::Email);

        let user = sqlx::query_as::<_, User>(&query)
            .bind(email_hash)
            .fetch_one(&self.pool)
            .await?;

        if let Some(date) = user.deleted_at {
            return Err(crate::error::ServerError::UserDeleted { date });
        };

        Ok(user)
    }

    /// Update current user.
    pub async fn update(&self, user: &User) -> Result<()> {
        sqlx::query!(
            r#"UPDATE users
                SET username = $1, email_hash = $2, email_cipher = $3, summary = $4, totp_secret = $5
                WHERE id = $6"#,
            user.username,
            user.email_hash,
            user.email_cipher,
            user.summary,
            user.totp_secret,
            user.id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete current user.
    pub async fn delete(&self, user_id: &str) -> Result<()> {
        sqlx::query!(
            r#"UPDATE users SET deleted_at = $1 WHERE id = $2"#,
            chrono::Utc::now().date_naive(),
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Insert a token linked to user into database.
    pub async fn insert_token(
        &self,
        token: &str,
        user_id: &str,
        ip: Option<String>,
    ) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO tokens (token, user_id, ip) VALUES ($1, $2, $3)"#,
            token,
            user_id,
            ip
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Field {
    Id,
    Email,
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Field::Id => write!(f, "id"),
            Field::Email => write!(f, "email_hash"),
        }
    }
}

fn get_by_field_query(field: Field) -> String {
    format!(
        r#"SELECT 
                u.id,
                u.username,
                u.locale,
                u.email_hash,
                u.email_cipher,
                u.totp_secret,
                u.summary,
                u.avatar,
                u.flags,
                u.password,
                u.created_at,
                u.deleted_at,
                CASE
                    WHEN COUNT(k.id) = 0 THEN '[]'
                    ELSE JSONB_AGG(
                        jsonb_build_object(
                            'id', cast(k.id as TEXT),
                            'owner', k.user_id,
                            'public_key_pem', k.key,
                            'created_at', k.created_at
                        )
                    )
                END AS public_keys
            FROM users u
            LEFT JOIN keys k ON k.user_id = u.id
            WHERE u.{field} = $1
            GROUP BY 
                u.id,
                u.username,
                u.locale,
                u.email_hash,
                u.email_cipher,
                u.avatar,
                u.flags,
                u.password,
                u.created_at,
                u.deleted_at;
            "#
    )
}
