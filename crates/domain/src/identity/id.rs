//! ID logic management.

use std::fmt;

use crate::error::{DomainError, Result};

/// Value object of a valid identifier.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserId(String);

impl UserId {
    /// Converts a [`String`] into a valid [`UserId`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string length is greater than 64
    /// characters or less than 2 characters.
    pub fn parse(id: String) -> Result<Self> {
        let trimmed = id.trim();
        let len = trimmed.len();
        if !(3..=64).contains(&len) {
            return Err(DomainError::InvalidIdFormat);
        }

        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(DomainError::InvalidIdFormat);
        }

        Ok(Self(trimmed.to_string()))
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
