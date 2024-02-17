#![forbid(unsafe_code)]
#![deny(
    dead_code,
    unused_imports,
    unused_mut,
    missing_docs,
    missing_debug_implementations
)]

//! # crypto
//!
//! little library using ring and fpe to encrypt,
//! decrypt and hash informations for Gravitalia.
//!
//! Supported hashing method:
//! - argon2;
//! - sha1;
//! - sha256.
//!
//! Supported encryption method:
//! - chacha20;
//! - fpe with AES256.
//!
//! # Hash with SHA.
//!
//! ```rust
//! println!("SHA256 of 'Hello world': {}", crypto::hash::sha256(b"Hello world"));
//! ```

/// Module to decrypt datas.
pub mod decrypt;
/// Module to encrypt datas.
pub mod encrypt;
/// Module to hash datas.
pub mod hash;

use ring::rand::{SecureRandom, SystemRandom};
use std::error::Error;
use std::fmt;

/// Error type for crypto errors.
#[derive(Debug)]
pub enum CryptoError {
    /// An error with absolutely no details.
    Unspecified,
    /// An error when converting bytes to `String`.
    UTF8Error,
    /// Failed decoding hex value.
    UnableDecodeHex,
    /// Related to `fpe` crate.
    InvalidRadix,
    /// Related to `fpe` crate.
    ExceedRadix,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::Unspecified => write!(f, "Unknown error"),
            CryptoError::UTF8Error => write!(f, "Bytes to `String` conversion failed."),
            CryptoError::UnableDecodeHex => write!(f, "This error is linked to the `hex` crate. It is impossible to decode an input value."),
            CryptoError::InvalidRadix => write!(f, "This error is linked to the `fpe` crate. The radix entered exceeds the maximum value (2..2^16)."),
            CryptoError::ExceedRadix => write!(f, "This error is linked to the `fpe` crate. The input radix is too small for the expected output radix, increase the radix."),
        }
    }
}

impl Error for CryptoError {}

const RADIX: u32 = 256;
const CHARS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&";
const CHARS_LENGTH: u8 = CHARS.len() as u8;

/// Generate random bytes cryptographically-secure PRNG seeded from the system's entropy pool.
///
/// # Examples
///
/// ```rust
/// use crypto::random_bytes;
///
/// println!("Crypto-secure 12 random bytes: {:?}", random_bytes(12));
/// ```
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];

    let sr = SystemRandom::new();
    sr.fill(&mut bytes).unwrap_or_default();

    bytes
}

/// Generate random string with thread-local cryptographically-secure PRNG seeded from the system's entropy pool.
///
/// # Examples
///
/// ```rust
/// use crypto::random_string;
///
/// println!("Crypto-secure 12 characters: {}", random_string(12));
/// ```
pub fn random_string(length: usize) -> String {
    let chars: Vec<char> = CHARS.chars().collect();
    let mut result = String::with_capacity(length);

    let random_bytes = random_bytes(length);

    for n in 0..length {
        result.push(chars[(random_bytes[n] % CHARS_LENGTH) as usize]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex_lite::Regex;

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(20);
        println!("{:?}", bytes);

        assert_eq!(bytes.len(), 20);
    }

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
