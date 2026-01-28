//! Data Transfer Objects for the application layer.
//!
//! DTOs are used to transfer data between layers without exposing domain
//! entities.

use domain::auth::email::EmailHash;
use domain::auth::password::{Password, PasswordHash};
use domain::identity::email::EmailAddress;
use domain::identity::id::UserId;
use domain::key::pem::PemFingerprint;

/// Request DTO for authentication.
#[derive(Debug, Clone)]
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
    pub ip_address: Option<String>,
}

/// Response DTO for authentication.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct CreateAccountRequestDto {
    /// User ID (vanity/username).
    pub user_id: String,
    /// Email address.
    pub email: EmailAddress,
    /// Password.
    pub password: Password,
    /// ISO 3166-1 alpha-2.
    pub locale: Option<String>,
    /// Invite code (optional).
    pub invite_code: Option<String>,
}

/// Request DTO for token refresh.
#[derive(Debug, Clone)]
pub struct RefreshTokenRequestDto {
    /// The refresh token.
    pub refresh_token: String,
    /// Client IP address.
    pub ip_address: Option<String>,
}

/// DTO for account data (used between application and repository).
#[derive(Debug, Clone)]
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
    pub created_at: String,
}
