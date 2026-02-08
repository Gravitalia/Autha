//! Database models for PostgreSQL.

use application::dto::{AccountDto, PublicKeyDto};
use application::error::{Result, ToInternal};
use chrono::{DateTime, NaiveDate, Utc};
use domain::auth::email::EmailHash;
use domain::auth::password::PasswordHash;
use domain::identity::id::UserId;
use domain::key::pem::PemFingerprint;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// User record as stored in the database.
#[derive(Debug, Clone, FromRow)]
pub struct UserRecord {
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
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    #[sqlx(json)]
    pub public_keys: Vec<PublicKeyRecord>,
}

/// Public key record embedded in UserRecord.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyRecord {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
    pub created_at: NaiveDate,
}

/// Refresh token record.
#[derive(Debug, Clone, FromRow)]
pub struct RefreshTokenRecord {
    pub id: i64,
    pub token: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

impl From<&PublicKeyRecord> for PublicKeyDto {
    fn from(k: &PublicKeyRecord) -> Self {
        Self {
            id: PemFingerprint::new(&k.id),
            owner: k.owner.clone(),
            public_key_pem: k.public_key_pem.clone(),
            created_at: k.created_at.to_string(),
        }
    }
}

impl UserRecord {
    /// Convert to [`AccountDto`].
    pub fn try_into_dto(self) -> Result<AccountDto> {
        Ok(AccountDto {
            id: UserId::parse(self.id).catch()?,
            username: self.username,
            email_hash: EmailHash::new(&self.email_hash),
            email_cipher: self.email_cipher,
            password_hash: PasswordHash::parse(&self.password).catch()?,
            totp_secret: self.totp_secret,
            locale: self.locale,
            summary: self.summary,
            avatar: self.avatar,
            flags: self.flags,
            created_at: self.created_at.timestamp() as u64,
            deleted_at: self.deleted_at.map(|d| d.timestamp() as u64),
            public_keys: self
                .public_keys
                .iter()
                .map(PublicKeyDto::from)
                .collect(),
        })
    }
}

impl From<&AccountDto> for UserRecord {
    fn from(dto: &AccountDto) -> Self {
        Self {
            id: dto.id.to_string(),
            username: dto.username.clone(),
            email_hash: dto.email_hash.to_string(),
            email_cipher: dto.email_cipher.clone(),
            totp_secret: dto.totp_secret.clone(),
            locale: dto.locale.clone(),
            summary: dto.summary.clone(),
            avatar: dto.avatar.clone(),
            flags: dto.flags,
            password: dto.password_hash.as_str().to_string(),
            created_at: DateTime::from_timestamp(dto.created_at as i64, 0)
                .unwrap_or_else(Utc::now),
            deleted_at: dto
                .deleted_at
                .and_then(|d| DateTime::from_timestamp(d as i64, 0)),
            public_keys: dto
                .public_keys
                .iter()
                .map(|k| PublicKeyRecord {
                    id: k.id.to_string(),
                    owner: k.owner.clone(),
                    public_key_pem: k.public_key_pem.clone(),
                    created_at: k
                        .created_at
                        .parse()
                        .unwrap_or_else(|_| Utc::now().date_naive()),
                })
                .collect(),
        }
    }
}
