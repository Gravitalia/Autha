//! Account repository port.

use async_trait::async_trait;
use domain::auth::email::EmailHash;
use domain::identity::id::UserId;

use crate::dto::AccountDto;
use crate::error::Result;

/// Port for account/user persistence operations.
#[async_trait]
pub trait AccountRepository: Send + Sync {
    /// Find an account by user ID.
    async fn find_by_id(&self, id: UserId) -> Result<Option<AccountDto>>;

    /// Find an account by email hash.
    async fn find_by_email_hash(
        &self,
        email_hash: EmailHash,
    ) -> Result<Option<AccountDto>>;

    /// Create a new account.
    async fn create(&self, account: &AccountDto) -> Result<()>;

    /// Update an existing account.
    async fn update(&self, account: &AccountDto) -> Result<()>;

    /// Soft delete an account.
    async fn delete(&self, id: &UserId) -> Result<()>;
}

/// Port for refresh token persistence.
#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    /// Store a new refresh token.
    async fn store(
        &self,
        token: &str,
        user_id: &UserId,
        ip_address: Option<&String>,
    ) -> Result<()>;

    /// Find the user ID associated with a refresh token.
    async fn find_user_id(&self, token: &str) -> Result<Option<UserId>>;

    /// Revoke a refresh token.
    async fn revoke(&self, token: &str) -> Result<()>;

    /// Revoke all refresh tokens for a user.
    async fn revoke_all_for_user(&self, user_id: &UserId) -> Result<()>;
}
