//! Email logic management.

use std::sync::LazyLock;

use regex::Regex;

use crate::error::{DomainError, Result};

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap()
});

/// Value object of a valid email address.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Converts a [`String`] into a valid [`EmailAddress`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string is not a valid email address.
    pub fn parse(email: &str) -> Result<Self> {
        if email.len() > 254 {
            return Err(DomainError::InvalidEmailFormat);
        }

        if EMAIL_RE.is_match(email) {
            Ok(Self(email.to_string()))
        } else {
            Err(DomainError::InvalidEmailFormat)
        }
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailAddress")
            .field("email", &"[REDACTED]")
            .finish()
    }
}

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
