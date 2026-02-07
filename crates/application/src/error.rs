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

    #[error("argument requires {excepted} minimum length")]
    TooSmall { excepted: usize },
    #[error("something went wrong")]
    Unknown,

    #[error("internal server error")]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl ApplicationError {
    pub fn internal<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Internal(Box::new(err))
    }
}

pub trait ToInternal<T> {
    fn catch(self) -> Result<T>;
}

impl<T, E> ToInternal<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn catch(self) -> Result<T> {
        self.map_err(|e| ApplicationError::Internal(Box::new(e)))
    }
}
