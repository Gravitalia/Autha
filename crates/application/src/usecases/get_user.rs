//! Get user use case implementation.

use std::sync::Arc;

use domain::identity::id::UserId;

use crate::dto::UserResponseDto;
use crate::error::{ApplicationError, Result};
use crate::ports::inbound::GetUser;
use crate::ports::outbound::Token;
use crate::ports::outbound::account::AccountRepository;

/// Get user use case service.
pub struct GetUserUseCase {
    account_repo: Arc<dyn AccountRepository>,
    _token: Arc<dyn Token>,
}

impl GetUserUseCase {
    pub fn new(
        account_repo: Arc<dyn AccountRepository>,
        _token: Arc<dyn Token>,
    ) -> Self {
        Self {
            account_repo,
            _token,
        }
    }
}

#[async_trait::async_trait]
impl GetUser for GetUserUseCase {
    async fn execute(&self, user_id: UserId) -> Result<UserResponseDto> {
        let parsed_id = UserId::parse(user_id.as_str().to_lowercase())
            .map_err(|_| ApplicationError::UserNotFound)?;

        let account = self
            .account_repo
            .find_by_id(&parsed_id)
            .await?
            .ok_or(ApplicationError::UserNotFound)?;

        if account.deleted_at.is_some() {
            return Err(ApplicationError::AccountDeleted {
                date: account.deleted_at.unwrap(),
            });
        }

        Ok(UserResponseDto {
            id: account.id.to_string(),
            username: account.username,
            avatar: account.avatar,
            summary: account.summary,
            flags: account.flags,
            public_keys: account.public_keys,
            created_at: account.created_at,
        })
    }
}
