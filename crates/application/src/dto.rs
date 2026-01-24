//! Data Transfer Objects for the application layer.
//!
//! DTOs are used to transfer data between layers without exposing domain
//! entities.

/// Request DTO for authentication.
#[derive(Debug, Clone)]
pub struct AuthRequestDto {
    /// Email address (optional, mutually exclusive with user_id).
    pub email: Option<String>,
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
    pub email: String,
    /// Password.
    pub password: String,
    /// Locale (e.g., "en", "fr").
    pub locale: Option<String>,
    /// Invite code (optional).
    pub invite_code: Option<String>,
    /// Client IP address.
    pub ip_address: Option<String>,
}

/// Response DTO for account creation.
#[derive(Debug, Clone)]
pub struct CreateAccountResponseDto {
    /// Access token (JWT).
    pub access_token: String,
    /// Refresh token.
    pub refresh_token: String,
    /// Token type (e.g., "Bearer").
    pub token_type: String,
    /// Expiration time in seconds.
    pub expires_in: u64,
}

/// Request DTO for token refresh.
#[derive(Debug, Clone)]
pub struct RefreshTokenRequestDto {
    /// The refresh token.
    pub refresh_token: String,
    /// Client IP address.
    pub ip_address: Option<String>,
}

/// Response DTO for token refresh.
#[derive(Debug, Clone)]
pub struct RefreshTokenResponseDto {
    /// New access token (JWT).
    pub access_token: String,
    /// New refresh token (rotated).
    pub refresh_token: String,
    /// Token type (e.g., "Bearer").
    pub token_type: String,
    /// Expiration time in seconds.
    pub expires_in: u64,
}

/// DTO for account data (used between application and repository).
#[derive(Debug, Clone, Default)]
pub struct AccountDto {
    pub id: String,
    pub username: String,
    pub email_hash: String,
    pub email_cipher: String,
    pub password_hash: String,
    pub totp_secret: Option<String>,
    pub locale: String,
    pub summary: Option<String>,
    pub avatar: Option<String>,
    pub flags: i32,
    pub created_at: u64,
    pub deleted_at: Option<String>,
    pub public_keys: Vec<PublicKeyDto>,
}

/// DTO for public key data.
#[derive(Debug, Clone, Default)]
pub struct PublicKeyDto {
    pub id: String,
    pub owner: String,
    pub public_key_pem: String,
    pub created_at: String,
}
