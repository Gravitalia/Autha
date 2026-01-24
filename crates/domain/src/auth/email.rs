//! Email logic.

/// Value object of a hashed email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailHash(String);

impl EmailHash {
    /// Create a new [`EmailHash`].
    pub fn new(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
