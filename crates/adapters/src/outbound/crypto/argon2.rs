//! Argon2id password hasher implementation.

use application::error::{Result, ToInternal};
use application::ports::outbound::PasswordHasher;
use argon2::password_hash::{
    PasswordHash, PasswordHasher as Argon2PasswordHasherTrait,
    PasswordVerifier, SaltString,
};
use argon2::{Argon2, Params, Version};
use domain::auth::password::{Password, PasswordHash as DomainPasswordHash};
use domain::error::DomainError;
use rand::rngs::OsRng;

const OUTPUT_LENGTH: usize = 32;

/// Argon2id password hasher adapter.
pub struct Argon2PasswordHasher {
    params: Params,
}

impl Argon2PasswordHasher {
    /// Create a new Argon2 hasher with custom parameters.
    pub fn new(
        memory_cost: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self> {
        let params = Params::new(
            memory_cost,
            iterations,
            parallelism,
            Some(OUTPUT_LENGTH),
        )
        .catch()?;

        Ok(Self { params })
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash(&self, password: &Password) -> Result<DomainPasswordHash> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            self.params.clone(),
        );

        let salt = SaltString::generate(&mut OsRng);

        let hash = argon2.hash_password(password.as_bytes(), &salt).catch()?;

        Ok(DomainPasswordHash::parse(hash.to_string())?)
    }

    fn verify(
        &self,
        password: &Password,
        hash: &DomainPasswordHash,
    ) -> Result<()> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            self.params.clone(),
        );

        let parsed_hash = PasswordHash::new(hash.as_str())
            .map_err(|_| DomainError::InvalidCredentials)?;

        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| DomainError::InvalidCredentials)?;

        Ok(())
    }
}
