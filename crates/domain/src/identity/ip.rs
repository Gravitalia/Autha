//! ID logic management.

use std::ops::Deref;

/// Value object of a valid identifier.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct EncryptedIp(String);

impl EncryptedIp {
    /// Converts a [`String`] into a valid [`EncryptedIp`].
    ///
    /// Never fails. Caller must ensure [`String`] is encrypted.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EncryptedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedIp")
            .field("ip", &"[REDACTED]")
            .finish()
    }
}

impl AsRef<str> for EncryptedIp {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for EncryptedIp {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
