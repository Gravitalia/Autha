use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::types::JsonValue;
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
    pub public_keys: Option<JsonValue>,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Key {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
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
            sqlx::query_as!(
                User,
                r#"SELECT 
                    u.vanity,
                    u.username,
                    u.email,
                    u.avatar,
                    u.flags,
                    u.password,
                    u.created_at,
                    CASE
                        WHEN COUNT(k.id) = 0 THEN NULL
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
                LEFT JOIN keys k ON k.user_id = u.vanity
                WHERE u.vanity = $1
                GROUP BY 
                    u.vanity, 
                    u.username, 
                    u.email, 
                    u.avatar, 
                    u.flags, 
                    u.password, 
                    u.created_at;
                "#,
                self.vanity,
            )
            .fetch_one(conn)
            .await
        } else if !self.email.is_empty() {
            sqlx::query_as!(
                User,
                r#"SELECT
                    u.vanity,
                    u.username,
                    u.email,
                    u.avatar,
                    u.flags,
                    u.password,
                    u.created_at,
                    CASE
                        WHEN COUNT(k.id) = 0 THEN NULL
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
                LEFT JOIN keys k ON k.user_id = u.vanity
                WHERE u.email = $1
                GROUP BY 
                    u.vanity, 
                    u.username, 
                    u.email, 
                    u.avatar, 
                    u.flags,
                    u.password, 
                    u.created_at;
                "#,
                self.email,
            )
            .fetch_one(conn)
            .await
        } else {
            Err(sqlx::Error::ColumnNotFound(
                "Missing column 'vanity' or 'email' column".to_owned(),
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
