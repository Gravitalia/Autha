//! SHA-256 hasher for non-password data (e.g., email lookups).

use application::ports::outbound::Hasher;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// SHA-256 hasher with pepper.
pub struct Sha256Hasher {
    pepper: Zeroizing<Vec<u8>>,
}

impl Sha256Hasher {
    pub fn new(pepper: Vec<u8>) -> Self {
        Self {
            pepper: Zeroizing::new(pepper),
        }
    }
}

impl Hasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.pepper);
        hasher.update(data);
        let result = hasher.finalize();

        hex::encode(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_hash() {
        let hasher = Sha256Hasher::new(b"pepper".to_vec());
        let hash1 = hasher.hash(b"test@example.com");
        let hash2 = hasher.hash(b"test@example.com");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_inputs() {
        let hasher = Sha256Hasher::new(b"pepper".to_vec());
        let hash1 = hasher.hash(b"test1@example.com");
        let hash2 = hasher.hash(b"test2@example.com");
        assert_ne!(hash1, hash2);
    }
}
