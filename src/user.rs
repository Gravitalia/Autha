use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

const TOKEN_LENGTH: usize = 64;

/// Database user representation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
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
    pub(crate) password: String,
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
    /// Update `vanity` of en empty [`User`].
    /// Do not work for fetched users.
    pub fn with_id(mut self, user_id: String) -> Self {
        self.id = user_id;
        self
    }

    /// Update `email` of an empty [`User`].
    /// Do not work for fetched users.
    pub fn with_email(mut self, email: String) -> Self {
        self.email = email;
        self
    }

    /// Update `password` of an empty [`User`].
    ///
    /// **WARNING: hash password before pass it here!**
    pub fn with_password(mut self, password: String) -> Self {
        self.password = password;
        self
    }

    /// Create a new user.
    pub async fn create(self, conn: &Pool<Postgres>) -> Result<Self, sqlx::Error> {
        if self.id.is_empty() && self.password.is_empty() {
            return Err(sqlx::Error::ColumnNotFound(
                "missing 'id' and 'password' columns".to_owned(),
            ));
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
            sqlx::query_as::<_, User>(&get_by_field_query("id"))
                .bind(self.id)
                .fetch_one(conn)
                .await
        } else if !self.email.is_empty() {
            sqlx::query_as::<_, User>(&get_by_field_query("email"))
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
    pub async fn generate_token(&self, conn: &Pool<Postgres>) -> Result<String, sqlx::Error> {
        if self.id.is_empty() {
            return Err(sqlx::Error::ColumnNotFound(
                "Missing column 'id' column".into(),
            ));
        }

        let token = Alphanumeric.sample_string(&mut OsRng, TOKEN_LENGTH);

        sqlx::query!(
            r#"INSERT INTO "tokens" (token, user_id) values ($1, $2)"#,
            token,
            self.id,
        )
        .execute(conn)
        .await?;

        Ok(token)
    }

    /// Update user data on database using structure.
    pub async fn update(self, conn: &Pool<Postgres>) -> Result<Self, sqlx::Error> {
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
    pub async fn delete(self, conn: &Pool<Postgres>) -> Result<(), sqlx::Error> {
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

fn get_by_field_query(field: &str) -> String {
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
