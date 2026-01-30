//! Interface for JWT/token operations.

use domain::auth::proof::AuthenticationProof;

use crate::error::Result;

/// Claims contained in an access token.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: u64,
    /// Issued at (Unix timestamp).
    pub iat: u64,
    /// JWT ID (unique identifier).
    pub jti: String,
    /// Scopes/permissions.
    pub scope: String,
}

/// Port for token signing and verification.
pub trait TokenSigner: Send + Sync {
    /// Create a signed access token for an authenticated user.
    fn create_access_token(
        &self,
        proof: &AuthenticationProof,
    ) -> Result<String>;

    /// Create a signed access token with custom claims.
    fn create_token(&self, claims: &TokenClaims) -> Result<String>;

    /// Decode and verify a token, returning its claims.
    fn verify_token(&self, token: &str) -> Result<TokenClaims>;

    /// Get the key ID used for signing.
    fn key_id(&self) -> &str;
}

/// Port for refresh token management.
pub trait RefreshTokenManager: Send + Sync {
    /// Generate a new refresh token.
    fn generate(&self) -> String;

    /// Get the default expiration time in seconds.
    fn expiration_seconds(&self) -> u64;
}

/// Aggregated token port combining all tokens operations.
pub trait Token: Send + Sync {
    fn signer(&self) -> &dyn TokenSigner;
    fn refresh_token(&self) -> &dyn RefreshTokenManager;
}
