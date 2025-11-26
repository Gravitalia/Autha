mod builder;
mod repository;
mod service;

pub use builder::*;
pub use repository::*;
pub use service::*;

use serde::{Deserialize, Serialize};

/// User as saved on database.
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
    #[serde(skip)]
    #[sqlx(skip)]
    pub invite: Option<String>,
    pub created_at: chrono::NaiveDate,
    pub deleted_at: Option<chrono::NaiveDate>,
    #[sqlx(json)]
    pub public_keys: Vec<Key>,
}

/// Public keys of a [`User`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Key {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
    pub created_at: chrono::NaiveDate,
}
