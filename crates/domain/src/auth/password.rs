//! Password logic.

use std::sync::LazyLock;

use regex::Regex;

use crate::error::{DomainError, Result};

static PASSWORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\$([a-z0-9-]{1,32})(?:\$v=(\d+))?(?:\$([^$]+))?\$([^$]+)\$([^$]+)$",
    )
    .unwrap()
});

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
        if !PASSWORD_RE.is_match(&pwd) {
            return Err(DomainError::InvalidCredentials);
        }

        Ok(Self(pwd))
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
