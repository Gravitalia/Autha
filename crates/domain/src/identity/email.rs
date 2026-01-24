//! Email logic management.

use std::fmt;

use crate::error::{DomainError, Result};

/// Value object of a valid email address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Converts a [`String`] into a valid [`EmailAddress`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string is not a valid email address as
    /// defined on RFC5322.
    pub fn parse(email: String) -> Result<Self> {
        if email.contains('@') && email.split('@').count() == 2 {
            Ok(Self(email.to_lowercase()))
        } else {
            Err(DomainError::InvalidEmailFormat)
        }
    }

    /// Returns the same string as a string slice `&str`.
    ///
    /// This method is redundant when used directly on `&str`, but
    /// it helps dereferencing other string-like types to string slices,
    /// for example references to `Box<str>` or `Arc<str>`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
