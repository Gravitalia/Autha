//! Data Transfer Objects for the application layer.
//!
//! DTOs are used to transfer data between layers without exposing domain
//! entities.

use domain::auth::email::EmailHash;
use domain::auth::password::{Password, PasswordHash};
use domain::identity::email::EmailAddress;
use domain::identity::id::UserId;
use domain::identity::ip::EncryptedIp;
use domain::key::pem::PemFingerprint;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

/// Request DTO for authentication.
pub struct AuthRequestDto {
    /// Email address (optional, mutually exclusive with user_id).
    pub email: Option<EmailAddress>,
    /// User ID (optional, mutually exclusive with email).
    pub user_id: Option<String>,
    /// Password.
    pub password: String,
    /// TOTP code (optional).
    pub totp_code: Option<String>,
    /// Client IP address.
    pub ip_address: Option<EncryptedIp>,
}

/// Response DTO for authentication.
#[derive(Serialize)]
pub struct AuthResponseDto {
    /// Access token (JWT).
    pub access_token: String,
    /// Refresh token.
    pub refresh_token: String,
    /// Token type (e.g., "Bearer").
    pub token_type: String,
    /// Expiration time in seconds.
    pub expires_in: u64,
}

/// Request DTO for account creation.
#[derive(Debug)]
pub struct CreateAccountRequestDto {
    /// User ID (vanity/username).
    pub user_id: UserId,
    /// Email address.
    pub email: EmailAddress,
    /// Password.
    pub password: Password,
    /// ISO 639-1.
    pub locale: Option<String>,
    /// Invite code (optional).
    pub invite_code: Option<String>,
    /// Client IP address.
    pub ip_address: Option<EncryptedIp>,
}

/// Request DTO for token refresh.
pub struct RefreshTokenRequestDto {
    /// The refresh token.
    pub refresh_token: String,
    /// Client IP address.
    pub ip_address: Option<EncryptedIp>,
}

/// DTO for account data (used between application and repository).
pub struct AccountDto {
    pub id: UserId,
    pub username: String,
    pub email_hash: EmailHash,
    pub email_cipher: String,
    pub password_hash: PasswordHash,
    pub totp_secret: Option<String>,
    pub locale: String,
    pub summary: Option<String>,
    pub avatar: Option<String>,
    pub flags: i32,
    pub created_at: u64,
    pub deleted_at: Option<u64>,
    pub public_keys: Vec<PublicKeyDto>,
}

/// DTO for public key data.
#[derive(Debug, Clone)]
pub struct PublicKeyDto {
    pub id: PemFingerprint,
    pub owner: String,
    pub public_key_pem: String,
    /// `yyyy-mm-dd` date.
    pub created_at: String,
}

impl Serialize for PublicKeyDto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("PublicKey", 4)?;
        s.serialize_field("id", &self.id.as_str())?;
        s.serialize_field("owner", &self.owner)?;
        s.serialize_field("public_key_pem", &self.public_key_pem)?;
        s.serialize_field("created_at", &self.created_at)?;
        s.end()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusDto {
    pub name: String,
    pub url: String,
    pub support: Option<String>,
    pub favicon: Option<String>,
    pub background: Option<String>,
    pub terms_of_service: Option<String>,
    pub privacy_policy: Option<String>,
    pub invite_only: bool,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponseDto {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub r#type: String,
    pub id: String,
    pub preferred_username: String,
    pub name: Option<String>,
    pub icon: Vec<String>,
    pub summary: Option<String>,
    pub flags: i32,
    pub public_keys: Vec<PublicKeyDto>,
    pub published: String,
    pub inbox: String,
    pub outbox: String,
    pub followers: String,
    pub following: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypedKeyDto {
    One(String),
    Multiple(Vec<String>),
    Remove(i32),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserDto {
    #[serde(alias = "preferredUsername", alias = "username")]
    pub username: Option<String>,
    pub summary: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_code: Option<String>,
    pub public_keys: Option<TypedKeyDto>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub new_password: Option<String>,
}
