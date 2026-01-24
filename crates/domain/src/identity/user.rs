//! User domain entity.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Represents a registered user within the system domain.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email_hash: String,
    pub email_cipher: String,
    pub totp_secret: Option<String>,
    pub locale: String,
    pub summary: Option<String>,
    pub avatar: Option<String>,
    pub flags: i32,
    pub password: String,
    pub ip: Option<String>,
    pub invite: Option<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<NaiveDate>,
    // pub public_keys: Vec<Key>,
}
