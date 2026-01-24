//! Account creation use case port.

use async_trait::async_trait;

use crate::dto::{CreateAccountRequestDto, CreateAccountResponseDto};
use crate::error::Result;

/// Inbound port for account creation.
#[async_trait]
pub trait CreateAccount: Send + Sync {
    /// Create a new user account.
    async fn execute(
        &self,
        request: CreateAccountRequestDto,
    ) -> Result<CreateAccountResponseDto>;
}
