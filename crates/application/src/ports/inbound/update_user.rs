//! Inbound port for updating a user.

use async_trait::async_trait;
use domain::identity::id::UserId;

use crate::dto::UpdateUserDto;
use crate::error::Result;

/// Use case interface for updating user information.
#[async_trait]
pub trait UpdateUser: Send + Sync {
    /// Updates the user with the given ID using the provided payload.
    /// Returns the list of updated public key IDs.
    async fn update(
        &self,
        user_id: &UserId,
        payload: UpdateUserDto,
    ) -> Result<Vec<String>>;
}
