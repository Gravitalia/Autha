use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

pub const TOKEN_LENGTH: u64 = 64;
const DEFAULT_LOCALE: &str = "en";

/// Database user representation.
#[derive(
    Clone, Debug, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow,
)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip)]
    pub email_hash: String,
    #[serde(skip)]
    pub email_cipher: String,
    #[serde(skip)]
    pub totp_secret: Option<String>,
    pub locale: String,
    pub summary: Option<String>,
    pub avatar: Option<String>,
    pub flags: i32,
    #[serde(skip)]
    pub password: String,
    #[sqlx(skip)]
    #[serde(skip)]
    pub ip: Option<String>,
    pub created_at: chrono::NaiveDate,
    pub deleted_at: Option<chrono::NaiveDate>,
    #[sqlx(json)]
    pub public_keys: Vec<Key>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Key {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
    pub created_at: chrono::NaiveDate,
}

impl User {
    /// Build a new [`User`].
    pub fn builder() -> Self {
        Self::default()
    }

    /// Update `vanity` of en empty [`User`].
    /// Do not work for fetched users.
    pub fn with_id<T: ToString>(mut self, user_id: T) -> Self {
        self.id = user_id.to_string();
        self
    }

    /// Update `locale` of an empty [`User`].
    pub fn with_locale(mut self, locale: Option<String>) -> Self {
        self.locale = locale.unwrap_or(DEFAULT_LOCALE.to_string());
        self
    }

    /// Update emails of an empty [`User`].
    /// Automatically hash and encrypt the email on `create`.
    pub fn with_email<T: ToString>(mut self, email: T) -> Self {
        self.email_cipher = email.to_string();
        self
    }

    /// Update `email_hash` field of a [`User`].
    pub fn with_email_hash<T: ToString>(mut self, email: T) -> Self {
        self.email_hash = email.to_string();
        self
    }

    /// Update `password` of an empty [`User`].
    pub fn with_password<T: ToString>(mut self, plain_text: T) -> Self {
        self.password = plain_text.to_string();
        self
    }

    /// Update `ip` of a [`User`].
    ///
    /// IP should be encrypted.
    pub fn with_ip(mut self, ip: Option<String>) -> Self {
        self.ip = ip;
        self
    }

    /// Create a new user.
    pub async fn create(
        mut self,
        crypto: &crate::crypto::Crypto,
        conn: &Pool<Postgres>,
    ) -> crate::error::Result<Self> {
        if self.id.is_empty() && self.password.is_empty() {
            return Err(crate::ServerError::MissingColumns(vec![
                "id".into(),
                "password".into(),
            ]));
        }

        if !self.password.is_empty() {
            self.password = crypto.pwd.hash_password(self.password)?;
        }

        self.email_hash = crypto.hasher.digest(&self.email_hash);
        self.email_cipher =
            crypto.symmetric.encrypt_and_hex(self.email_cipher)?;

        sqlx::query!(
            r#"INSERT INTO "users" (id, username, locale, email_hash, email_cipher, password) VALUES ($1, $2, $3, $4, $5, $6)"#,
            self.id.to_lowercase(),
            self.id,
            self.locale,
            self.email_hash,
            self.email_cipher,
            self.password,
        )
        .execute(conn)
        .await?;

        tracing::trace!(user_id = self.id, "new user created on postgres");

        Ok(self)
    }

    /// Get data on a user.
    pub async fn get(
        &mut self,
        conn: &Pool<Postgres>,
    ) -> crate::error::Result<Self> {
        // Use `Option<T>` instead of `String` would complicate other functions.
        // We lose a little idiomaticity in favor of simpler usage later on.
        let (query, param) =
            match (self.id.is_empty(), self.email_hash.is_empty()) {
                (false, _) => (get_by_field_query(Field::Id), &self.id),
                (true, false) => {
                    (get_by_field_query(Field::Email), &self.email_hash)
                },
                _ => {
                    return Err(sqlx::Error::ColumnNotFound(
                        "missing column 'id' or 'email_hash' column".to_owned(),
                    )
                    .into());
                },
            };

        let user = sqlx::query_as::<_, User>(&query)
            .bind(param)
            .fetch_one(conn)
            .await?;

        if let Some(date) = user.deleted_at {
            return Err(crate::error::ServerError::UserDeleted { date });
        };

        Ok(user)
    }

    /// Generate a token for this specific user.
    pub async fn generate_token(
        &self,
        conn: &Pool<Postgres>,
    ) -> Result<String, sqlx::Error> {
        if self.id.is_empty() {
            return Err(sqlx::Error::ColumnNotFound(
                "Missing column 'id' column".into(),
            ));
        }

        let mut bytes = [0u8; TOKEN_LENGTH as usize / 2];
        OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);

        sqlx::query!(
            r#"INSERT INTO "tokens" (token, user_id, ip) values ($1, $2, $3)"#,
            token,
            self.id,
            self.ip,
        )
        .execute(conn)
        .await?;

        tracing::trace!(user_id = self.id, "new session token");

        Ok(token)
    }

    /// Update user data on database using structure.
    pub async fn update(
        self,
        conn: &Pool<Postgres>,
    ) -> Result<Self, sqlx::Error> {
        if self.id.is_empty() {
            return Err(sqlx::Error::ColumnNotFound(
                "Missing column 'id' column".into(),
            ));
        }

        sqlx::query!(
            r#"UPDATE "users"
            SET username = $1, email_hash = $2, email_cipher = $3, summary = $4, totp_secret = $5
            WHERE id = $6"#,
            self.username,
            self.email_hash,
            self.email_cipher,
            self.summary,
            self.totp_secret,
            self.id
        )
        .execute(conn)
        .await?;

        Ok(self)
    }

    /// Delete user from database (with 30 days retention).
    pub async fn delete(
        self,
        conn: &Pool<Postgres>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"UPDATE "users" SET deleted_at = $1 WHERE id = $2"#,
            chrono::Utc::now().date_naive(),
            self.id
        )
        .execute(conn)
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
