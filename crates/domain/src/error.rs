//! Custom error handler for domain (core).

use crate::key::public_key::KeyError;

pub type Result<T> = std::result::Result<T, DomainError>;

/// Enum representing custom domain errors.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("validation failed on {field} with {message}")]
    ValidationFailed { field: String, message: String },

    #[error("invalid email formatting")]
    InvalidEmailFormat,
    #[error("id must be between 2 and 22 characters length")]
    InvalidIdFormat,

    #[error(transparent)]
    PublicKey(#[from] KeyError),
    #[error("failed to encode pem in der format")]
    Der,

    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("TOTP code is required")]
    TotpRequired,
    #[error("TOTP code is invalid")]
    InvalidTotpCode,
    #[error("TOTP secret has invalid format")]
    InvalidTotpSecret,
    #[error("password must be at least {min_length} characters")]
    WeakPassword { min_length: usize },
}
