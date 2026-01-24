//! Interfaces for cryptographic operations.

use domain::auth::factor::{TotpCode, TotpConfig, TotpSecret};
use domain::auth::password::{Password, PasswordHash};

use crate::error::Result;

/// Port for password hashing operations.
pub trait PasswordHasher: Send + Sync {
    /// Hash a password using a secure algorithm.
    fn hash(&self, password: &Password) -> Result<PasswordHash>;

    /// Verify a password against a stored hash.
    fn verify(&self, password: &Password, hash: &PasswordHash) -> Result<()>;
}

/// Port for TOTP (Time-based One-Time Password) operations.
pub trait TotpGenerator: Send + Sync {
    /// Generate a TOTP code for the given secret at the current time.
    fn generate(
        &self,
        secret: &TotpSecret,
        config: &TotpConfig,
    ) -> Result<TotpCode>;

    /// Verify a TOTP code against a secret.
    fn verify(
        &self,
        code: &TotpCode,
        secret: &TotpSecret,
        config: &TotpConfig,
    ) -> Result<bool>;
}

/// Port for symmetric encryption operations.
pub trait SymmetricEncryption: Send + Sync {
    /// Encrypt plaintext data.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext data.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Encrypt and encode as hex string.
    fn encrypt_to_hex(&self, plaintext: &[u8]) -> Result<String>;

    /// Decrypt from hex-encoded ciphertext.
    fn decrypt_from_hex(&self, hex_ciphertext: &str) -> Result<Vec<u8>>;
}

/// Port for hashing operations (non-password, e.g., email hashing).
pub trait Hasher: Send + Sync {
    /// Compute a deterministic hash of the input.
    fn hash(&self, data: &[u8]) -> String;
}

/// Port for secure random generation.
pub trait SecureRandom: Send + Sync {
    /// Generate random bytes.
    fn random_bytes(&self, length: usize) -> Vec<u8>;

    /// Generate a random alphanumeric string.
    fn random_string(&self, length: usize) -> String;
}

/// Aggregated crypto port combining all cryptographic operations.
pub trait CryptoPort: Send + Sync {
    fn password_hasher(&self) -> &dyn PasswordHasher;
    fn totp_generator(&self) -> &dyn TotpGenerator;
    fn symmetric_encryption(&self) -> &dyn SymmetricEncryption;
    fn hasher(&self) -> &dyn Hasher;
    fn secure_random(&self) -> &dyn SecureRandom;
}
