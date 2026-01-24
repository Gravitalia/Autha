//! Password logic.

use crate::error::{DomainError, Result};

/// Value object of a password.
#[derive(Clone)]
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
                min_length: Self::MAX_LENGTH,
            });
        }

        if value.len() > Self::MAX_LENGTH {
            return Err(DomainError::WeakPassword {
                min_length: Self::MAX_LENGTH,
            });
        }

        Ok(Self(value))
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
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
    /// Create a new [`PasswordHash`].
    pub fn new(phc_string: impl Into<String>) -> Self {
        Self(phc_string.into())
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
