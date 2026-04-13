//! ID logic management.

use std::fmt;

use crate::error::{DomainError, Result};

/// Value object of a valid identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId(String);

impl UserId {
    /// Converts a bytes-like input into a valid [`UserId`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string length is greater than 64
    /// characters or less than 3 characters.
    pub fn parse<B: AsRef<[u8]>>(bytes: B) -> Result<Self> {
        let trimmed = Self::validate(bytes.as_ref())?;

        let s = std::str::from_utf8(trimmed)
            .map_err(|_| DomainError::InvalidIdFormat)?
            .to_string();

        Ok(Self(s))
    }

    fn validate(bytes: &[u8]) -> Result<&[u8]> {
        let start = bytes
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .unwrap_or(0);
        let end = bytes
            .iter()
            .rposition(|&b| !b.is_ascii_whitespace())
            .map_or(0, |p| p + 1);

        if start >= end {
            return Err(DomainError::InvalidIdFormat);
        }

        let trimmed = &bytes[start..end];
        let len = trimmed.len();

        if !(3..=64).contains(&len) {
            return Err(DomainError::InvalidIdFormat);
        }

        for &b in trimmed {
            if !(b.is_ascii_alphanumeric() || b == b'_') {
                return Err(DomainError::InvalidIdFormat);
            }
        }

        Ok(trimmed)
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(kani)]
impl UserId {
    pub fn dummy_for_kani() -> Self {
        Self(String::new())
    }
}

#[cfg(kani)]
mod proof {
    use super::*;

    #[kani::proof]
    #[kani::unwind(66)]
    fn prove_user_id_validation_logic() {
        let bytes = kani::vec::any_vec::<u8, 65>();

        match UserId::validate(&bytes) {
            Ok(trimmed) => {
                let l = trimmed.len();
                assert!(l >= 3 && l <= 64);
                assert!(
                    trimmed
                        .iter()
                        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
                );
            },
            Err(e) => {
                assert!(matches!(e, DomainError::InvalidIdFormat));
            },
        }
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn prove_static_logic() {
        assert!(UserId::validate(b"a@b").is_err());
        assert!(UserId::validate(b"   ab   ").is_err());
        assert!(UserId::validate(b"valid_id_123").is_ok());
    }
}
