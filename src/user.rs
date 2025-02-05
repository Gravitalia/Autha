use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

const TOKEN_LENGTH: usize = 64;

/// Database user representation.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub vanity: String,
    pub username: String,
    #[serde(skip)]
    pub email: String,
    pub avatar: Option<String>,
    pub flags: i32,
    #[serde(skip)]
    pub(crate) password: String,
    pub created_at: chrono::NaiveDate,
}

impl User {
    /// Update `vanity` of [`User`].
    pub fn with_vanity(mut self, vanity: String) -> Self {
        self.vanity = vanity;
        self
    }

    /// Update `email` of [`User`].
    pub fn with_email(mut self, email: String) -> Self {
        self.email = email;
        self
    }

    /// Get data on a user.
    pub async fn get(self, conn: &Pool<Postgres>) -> Result<Self, sqlx::Error> {
        if !self.vanity.is_empty() {
            Ok(sqlx::query_as!(
                    User,
                    r#"SELECT vanity, username, email, avatar, flags, password, created_at FROM users WHERE vanity = $1"#,
                    self.vanity,
                )
                .fetch_one(conn)
                .await?)
        } else if !self.email.is_empty() {
            Ok(sqlx::query_as!(
                    User,
                    "SELECT vanity, username, email, avatar, flags, password, created_at FROM users WHERE email = $1",
                    self.email,
                )
                .fetch_one(conn)
                .await?)
        } else {
            Err(sqlx::Error::ColumnNotFound(
                "Missing column 'vanity' or 'email' column".into(),
            ))
        }
    }

    /// Generate a token for this specific user.
    pub async fn generate_token(&self, conn: &Pool<Postgres>) -> Result<String, sqlx::Error> {
        if self.vanity.is_empty() {
            return Err(sqlx::Error::ColumnNotFound(
                "Missing column 'vanity' column".into(),
            ));
        }

        let token = Alphanumeric.sample_string(&mut OsRng, TOKEN_LENGTH);

        sqlx::query!(
            r#"INSERT INTO "tokens" (token, user_vanity) values ($1, $2)"#,
            token,
            self.vanity,
        )
        .execute(conn)
        .await?;

        Ok(token)
    }
}
