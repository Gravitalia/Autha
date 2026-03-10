//! Account creation use case port.

use std::sync::Arc;

use async_trait::async_trait;

use crate::dto::{AuthResponseDto, CreateAccountRequestDto};
use crate::error::Result;

/// Inbound port for account creation.
#[async_trait]
pub trait CreateAccount: Send + Sync {
    /// Create a new user account.
    async fn execute(
        &self,
        request: CreateAccountRequestDto,
    ) -> Result<AuthResponseDto>;
}

#[async_trait]
impl<T: CreateAccount + ?Sized> CreateAccount for Arc<T> {
    async fn execute(
        &self,
        request: CreateAccountRequestDto,
    ) -> Result<AuthResponseDto> {
        self.as_ref().execute(request).await
    }
}
