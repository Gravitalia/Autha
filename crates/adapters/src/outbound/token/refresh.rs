//! Secure refresh token generator.

use application::ports::outbound::RefreshTokenManager;
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::OsRng;

const DEFAULT_TOKEN_LENGTH: usize = 48;
const DEFAULT_EXPIRATION_SECONDS: u64 = 60 * 60 * 24 * 15; // 15 days.

/// Cryptographically secure refresh token generator.
pub struct SecureRefreshTokenManager {
    token_length: usize,
    expiration_seconds: u64,
}

impl SecureRefreshTokenManager {
    pub fn new() -> Self {
        Self {
            token_length: DEFAULT_TOKEN_LENGTH,
            expiration_seconds: DEFAULT_EXPIRATION_SECONDS,
        }
    }

    pub fn with_expiration(mut self, seconds: u64) -> Self {
        self.expiration_seconds = seconds;
        self
    }
}

impl Default for SecureRefreshTokenManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshTokenManager for SecureRefreshTokenManager {
    fn generate(&self) -> String {
        Alphanumeric.sample_string(&mut OsRng, self.token_length)
    }

    fn expiration_seconds(&self) -> u64 {
        self.expiration_seconds
    }
}
