//! Password logic.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{DomainError, Result};

/// Value object of a password.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Password(String);

impl Password {
    /// Maximum password length.
    pub const MAX_LENGTH: usize = 255;
    /// Minimum password length.
    pub const MIN_LENGTH: usize = 8;

    /// Create a new [`Password`] with basic validation.
    ///
    /// Strength validation is done at application layer.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();

        if value.len() < Self::MIN_LENGTH {
            return Err(DomainError::WeakPassword {
                min_length: Self::MIN_LENGTH,
            });
        }

        if value.len() > Self::MAX_LENGTH {
            return Err(DomainError::ValidationFailed {
                field: "password".into(),
                message: format!(
                    "password must be at most {} characters",
                    Self::MAX_LENGTH
                ),
            });
        }

        Ok(Self(value))
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns a byte slice of this `String`'s contents.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Password")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A hashed password stored in the database.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    /// Converts a [`String`] into a valid [`PasswordHash`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string is not in PHC format.
    pub fn parse(phc_string: impl Into<String>) -> Result<Self> {
        let pwd = phc_string.into();

        if !Self::validate_phc(pwd.as_bytes()) {
            return Err(DomainError::InvalidCredentials);
        }

        Ok(Self(pwd))
    }

    fn validate_phc(bytes: &[u8]) -> bool {
        if bytes.is_empty() || bytes[0] != b'$' {
            return false;
        }

        let mut segments = [&[] as &[u8]; 5];
        let mut count = 0;

        for part in bytes[1..].split(|&b| b == b'$') {
            if count >= 5 {
                return false;
            }
            segments[count] = part;
            count += 1;
        }

        if count < 3 {
            return false;
        }

        let id = segments[0];
        if id.is_empty() || id.len() > 32 {
            return false;
        }
        for &b in id {
            if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'-' {
                return false;
            }
        }

        let salt = segments[count - 2];
        if salt.is_empty() {
            return false;
        }

        let hash = segments[count - 1];
        if hash.is_empty() {
            return false;
        }

        let middle_count = count - 3;

        if middle_count == 1 {
            let mid = segments[1];
            if mid.is_empty() {
                return false;
            }
        } else if middle_count == 2 {
            let mid1 = segments[1];
            let mid2 = segments[2];

            if mid1.len() < 3 || !mid1.starts_with(b"v=") {
                return false;
            }
            for &b in &mid1[2..] {
                if !b.is_ascii_digit() {
                    return false;
                }
            }

            if mid2.is_empty() {
                return false;
            }
        }

        true
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordHash")
            .field("phc_string", &"[REDACTED]")
            .finish()
    }
}

#[cfg(kani)]
mod proof {
    use super::*;

    /*#[kani::proof]
    #[kani::unwind(261)]
    fn prove_password_security_rules() {
        let len: usize = kani::any_where(|&l| {
            (l <= 10) || (l >= 250 && l <= 260)
        });
        let bytes = [b'A'; 260];
        let slice = &bytes[..len];

        if let Ok(s) = std::str::from_utf8(slice) {
            match Password::new(s) {
                Ok(pwd) => {
                    assert!(pwd.as_str().len() >= Password::MIN_LENGTH);
                    assert!(pwd.as_str().len() <= Password::MAX_LENGTH);
                },
                Err(DomainError::WeakPassword { .. }) => {
                    assert!(len < Password::MIN_LENGTH);
                },
                Err(DomainError::ValidationFailed { .. }) => {
                    assert!(len > Password::MAX_LENGTH);
                },
                _ => unreachable!(),
            }
        }
    }*/

    #[kani::proof]
    #[kani::unwind(17)]
    fn prove_phc_format_invariants() {
        let bytes: [u8; 16] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 16);
        let slice = &bytes[..len];

        let is_valid = PasswordHash::validate_phc(slice);

        if is_valid {
            assert!(slice.len() > 0);
            assert_eq!(slice[0], b'$');

            let dollar_count = slice.iter().filter(|&&b| b == b'$').count();
            assert!(dollar_count >= 3 && dollar_count <= 5);

            let first_segment_end = slice[1..]
                .iter()
                .position(|&b| b == b'$')
                .unwrap_or(slice.len() - 1);
            let id_segment = &slice[1..=first_segment_end];

            assert!(!id_segment.is_empty());
            assert!(id_segment.len() <= 32);

            for &b in id_segment {
                assert!(
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-',
                );
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(17)]
    fn prove_phc_memory_safety() {
        let bytes: [u8; 16] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 16);
        let _ = PasswordHash::validate_phc(&bytes[..len]);
    }
}
