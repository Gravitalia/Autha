use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

pub const TOKEN_LENGTH: u64 = 64;

/// Database user representation.
#[derive(
    Clone, Debug, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow,
)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip)]
    pub email: String,
    #[serde(skip)]
    pub totp_secret: Option<String>,
    pub summary: Option<String>,
    pub avatar: Option<String>,
    pub flags: i32,
    #[serde(skip)]
    pub password: String,
    #[sqlx(skip)]
    #[serde(skip)]
    pub ip: Option<String>,
    pub created_at: chrono::NaiveDate,
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

    /// Update `email` of an empty [`User`].
    /// Do not work for fetched users.
    pub fn with_email<T: ToString>(mut self, email: T) -> Self {
        self.email = email.to_string();
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
        crypto: &crate::crypto::Cipher,
        conn: &Pool<Postgres>,
    ) -> crate::error::Result<Self> {
        if self.id.is_empty() && self.password.is_empty() {
            return Err(crate::ServerError::MissingColumns(vec![
                "id".into(),
                "password".into(),
            ]));
        }

        if !self.password.is_empty() {
            self.password = crypto.hash_password(self.password).await?;
        }

        sqlx::query!(
            r#"INSERT INTO "users" (id, username, email, password) VALUES ($1, $2, $3, $4)"#,
            self.id.to_lowercase(),
            self.id,
            self.email,
            self.password,
        )
        .execute(conn)
        .await?;

        Ok(self)
    }

    /// Get data on a user.
    pub async fn get(self, conn: &Pool<Postgres>) -> Result<Self, sqlx::Error> {
        if !self.id.is_empty() {
            sqlx::query_as::<_, User>(&get_by_field_query(Field::Id))
                .bind(self.id)
                .fetch_one(conn)
                .await
        } else if !self.email.is_empty() {
            sqlx::query_as::<_, User>(&get_by_field_query(Field::Email))
                .bind(self.email)
                .fetch_one(conn)
                .await
        } else {
            Err(sqlx::Error::ColumnNotFound(
                "missing column 'id' or 'email' column".to_owned(),
            ))
        }
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

        let token =
            Alphanumeric.sample_string(&mut OsRng, TOKEN_LENGTH as usize);

        sqlx::query!(
            r#"INSERT INTO "tokens" (token, user_id, ip) values ($1, $2, $3)"#,
            token,
            self.id,
            self.ip,
        )
        .execute(conn)
        .await?;

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
            r#"UPDATE "users" SET username = $1, email = $2, summary = $3, totp_secret = $4 WHERE id = $5"#,
            self.username,
            self.email,
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
            Field::Email => write!(f, "email"),
        }
    }
}

fn get_by_field_query(field: Field) -> String {
    format!(
        r#"SELECT 
                u.id,
                u.username,
                u.email,
                u.totp_secret,
                u.summary,
                u.avatar,
                u.flags,
                u.password,
                u.created_at,
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
                u.email, 
                u.avatar, 
                u.flags, 
                u.password, 
                u.created_at;
            "#
    )
}
