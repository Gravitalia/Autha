//! Authentication use case port.

use async_trait::async_trait;

use crate::dto::{AuthRequestDto, AuthResponseDto};
use crate::error::Result;

/// Inbound port for user authentication.
#[async_trait]
pub trait Authenticate: Send + Sync {
    /// Authenticate a user with credentials.
    async fn execute(
        &self,
        request: AuthRequestDto,
    ) -> Result<AuthResponseDto>;
}
