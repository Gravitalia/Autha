//! Custom error handler for domain (core).

use crate::key::public_key::KeyError;

pub type Result<T> = std::result::Result<T, DomainError>;

/// Enum representing custom domain errors.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("invalid email formatting")]
    InvalidEmailFormat,
    #[error("id must be between 2 and 22 characters length")]
    InvalidIdFormat,

    #[error(transparent)]
    PublicKey(#[from] KeyError),
    #[error("failed to encode pem in der format")]
    Der,
}
