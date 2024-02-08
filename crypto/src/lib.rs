// Clippy lint.
#![deny(missing_docs)]
//! # crypto
//!
//! little library using ring and fpe to encrypt,
//! decrypt and hash informations for Gravitalia.
//!
//! # Hash with SHA.
//!
//! ```rust
//! println!("SHA256 of 'Hello world': {}", crypto::hash::sha256(b"Hello world").unwrap_or_default());
//! ```

/// Module to decrypt datas.
pub mod decrypt;
/// Module to encrypt datas.
pub mod encrypt;
/// Module to hash datas.
pub mod hash;

use rand::rngs::OsRng;
use rand::Rng;

/// Generate random string with thread-local cryptographically-secure PRNG seeded from the system's entropy pool.
pub fn random_string(length: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&"
        .chars()
        .collect();
    let mut result = String::with_capacity(length);
    let mut rng = OsRng;

    for _ in 0..length {
        result.push(chars[rng.gen_range(0..62)]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex_lite::Regex;

    #[test]
    fn test_random_string() {
        let str = random_string(20);
        assert_eq!(str.len(), 20);
        assert_eq!(
            Regex::new(
                r"[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&]*"
            )
            .unwrap()
            .find_iter(&str)
            .count(),
            1
        );
    }
}
