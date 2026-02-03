//! Cryptographic adapters.

mod argon2;

use application::error::Result;
use application::ports::outbound::{
    CryptoPort, Hasher, PasswordHasher, SecureRandom, SymmetricEncryption,
    TotpGenerator,
};

use crate::outbound::crypto::argon2::Argon2PasswordHasher;

/// Aggregated crypto adapter implementing all crypto ports.
pub struct CryptoAdapter {
    password_hasher: Argon2PasswordHasher,
}

impl CryptoAdapter {
    /// Create a new [`CryptoAdapter`].
    pub fn new(
        _master_key: zeroize::Zeroizing<Vec<u8>>,
        _salt: Vec<u8>,
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
        })
    }
}

impl CryptoPort for CryptoAdapter {
    fn password_hasher(&self) -> &dyn PasswordHasher {
        &self.password_hasher
    }

    fn totp_generator(&self) -> &dyn TotpGenerator {
        unimplemented!()
    }

    fn symmetric_encryption(&self) -> &dyn SymmetricEncryption {
        unimplemented!()
    }

    fn hasher(&self) -> &dyn Hasher {
        unimplemented!()
    }

    fn secure_random(&self) -> &dyn SecureRandom {
        unimplemented!()
    }
}
