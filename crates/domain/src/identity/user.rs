//! User domain entity.

use chrono::{DateTime, NaiveDate, Utc};

use crate::auth::password::PasswordHash;
use crate::identity::email::EmailAddress;
use crate::identity::id::UserId;
use crate::key::public_key::Key;

/// Represents a registered user within the system domain.
#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub id: Option<UserId>,
    pub username: String,
    pub email: Option<EmailAddress>,
    pub totp_secret: Option<String>,
    pub locale: String,
    pub summary: Option<String>,
    pub avatar: Option<String>,
    pub flags: i32,
    pub password: PasswordHash,
    pub ip: Option<String>,
    pub invite: Option<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<NaiveDate>,
    pub public_keys: Vec<Key>,
}
