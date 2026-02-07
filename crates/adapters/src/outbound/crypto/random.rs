//! Secure random generation using OS RNG.

use application::error::{Result, ToInternal};
use application::ports::outbound::SecureRandom;
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};

/// OS-based secure random generator.
pub struct OsRngRandom;

impl OsRngRandom {
    pub fn new() -> Self {
        Self
    }
}

impl SecureRandom for OsRngRandom {
    fn random_bytes(&self, length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        OsRng.try_fill_bytes(&mut bytes).catch()?;
        Ok(bytes)
    }

    fn random_string(&self, length: usize) -> Result<String> {
        Ok(OsRng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect())
    }

    fn random_hex(&self, byte_length: usize) -> Result<String> {
        let bytes = self.random_bytes(byte_length)?;
        Ok(hex::encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let rng = OsRngRandom::new();
        let bytes1 = rng.random_bytes(32).unwrap();
        let bytes2 = rng.random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_string() {
        let rng = OsRngRandom::new();
        let str1 = rng.random_string(16).unwrap();
        let str2 = rng.random_string(16).unwrap();

        assert_eq!(str1.len(), 16);
        assert!(str1.chars().all(|c| c.is_alphanumeric()));
        assert_ne!(str1, str2);
    }
}
