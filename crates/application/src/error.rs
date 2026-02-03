//! Application-level errors.

use domain::error::DomainError;

pub type Result<T> = std::result::Result<T, ApplicationError>;

/// Errors that can occur in the application layer.
#[derive(Debug, thiserror::Error)]
pub enum ApplicationError {
    #[error(transparent)]
    Domain(#[from] DomainError),

    #[error("user not found")]
    UserNotFound,
    #[error("user is deleted since {date}")]
    AccountDeleted { date: u64 },

    #[error("{cause}")]
    Crypto { cause: String },

    #[error("something went wrong")]
    Unknown,
}
