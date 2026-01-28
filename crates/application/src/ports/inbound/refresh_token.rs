//! Token refresh use case port.

use async_trait::async_trait;

use crate::dto::{AuthResponseDto, RefreshTokenRequestDto};
use crate::error::Result;

/// Inbound port for refreshing access tokens.
#[async_trait]
pub trait RefreshAccessToken: Send + Sync {
    /// Refresh an access token using a refresh token.
    async fn execute(
        &self,
        request: RefreshTokenRequestDto,
    ) -> Result<AuthResponseDto>;
}
