//! Cryptographic adapters.

mod aes;
mod argon2;
mod totp;

use application::error::Result;
use application::ports::outbound::{
    CryptoPort, Hasher, PasswordHasher, SecureRandom, SymmetricEncryption,
    TotpGenerator,
};

use crate::outbound::crypto::aes::AesGcmEncryption;
use crate::outbound::crypto::argon2::Argon2PasswordHasher;
use crate::outbound::crypto::totp::HmacTotpGenerator;

/// Aggregated crypto adapter implementing all crypto ports.
pub struct CryptoAdapter {
    password_hasher: Argon2PasswordHasher,
    totp_generator: HmacTotpGenerator,
    symmetric_encryption: AesGcmEncryption,
}

impl CryptoAdapter {
    /// Create a new [`CryptoAdapter`].
    pub fn new(
        master_key: zeroize::Zeroizing<Vec<u8>>,
        salt: Vec<u8>,
        argon_memory_cost: u32,
        argon_iterations: u32,
        argon_parallelism: u32,
    ) -> Result<Self> {
        Ok(Self {
            password_hasher: Argon2PasswordHasher::new(
                argon_memory_cost,
                argon_iterations,
                argon_parallelism,
            )?,
            totp_generator: HmacTotpGenerator::new(),
            symmetric_encryption: AesGcmEncryption::new(master_key, salt)?,
        })
    }
}

impl CryptoPort for CryptoAdapter {
    fn password_hasher(&self) -> &dyn PasswordHasher {
        &self.password_hasher
    }

    fn totp_generator(&self) -> &dyn TotpGenerator {
        &self.totp_generator
    }

    fn symmetric_encryption(&self) -> &dyn SymmetricEncryption {
        &self.symmetric_encryption
    }

    fn hasher(&self) -> &dyn Hasher {
        unimplemented!()
    }

    fn secure_random(&self) -> &dyn SecureRandom {
        unimplemented!()
    }
}
