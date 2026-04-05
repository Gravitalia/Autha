//! Get user use case port.

use domain::identity::id::UserId;

use crate::dto::UserResponseDto;
use crate::error::Result;

/// Inbound port to get a user.
#[async_trait::async_trait]
pub trait GetUser: Send + Sync {
    /// Get a user with its ID.
    async fn execute(&self, user_id: UserId) -> Result<UserResponseDto>;
}
