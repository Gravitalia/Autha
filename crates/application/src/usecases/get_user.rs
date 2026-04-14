//! Get user use case implementation.

use std::sync::Arc;

use domain::identity::id::UserId;

use crate::dto::{StatusDto, UserResponseDto};
use crate::error::{ApplicationError, Result};
use crate::ports::inbound::GetUser;
use crate::ports::outbound::Token;
use crate::ports::outbound::account::AccountRepository;

/// Get user use case service.
pub struct GetUserUseCase {
    account_repo: Arc<dyn AccountRepository>,
    _token: Arc<dyn Token>,
    configuration: StatusDto,
}

impl GetUserUseCase {
    pub fn new(
        account_repo: Arc<dyn AccountRepository>,
        _token: Arc<dyn Token>,
        configuration: StatusDto,
    ) -> Self {
        Self {
            account_repo,
            _token,
            configuration,
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

        if let Some(date) = account.deleted_at {
            return Err(ApplicationError::AccountDeleted { date });
        }

        let published_date =
            chrono::DateTime::from_timestamp(account.created_at as i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();
        let url = url::Url::parse(&self.configuration.url)
            .map_err(|err| ApplicationError::Internal(Box::new(err)))?;
        let user_url = format!(
            "{}://{}/users/{}",
            url.scheme(),
            url.host().map(|u| u.to_string()).unwrap_or_default(),
            account.username
        );

        Ok(UserResponseDto {
            context: vec![
                "https://www.w3.org/ns/activitystreams".to_string(),
                "https://w3id.org/security/v1".to_string(),
            ],
            r#type: "Person".to_string(),
            id: user_url.clone(),
            preferred_username: account.username.clone(),
            name: Some(account.username),
            summary: account.summary,
            flags: account.flags,
            public_keys: account.public_keys,
            inbox: format!("{}/inbox", user_url),
            outbox: format!("{}/outbox", user_url),
            followers: format!("{}/followers", user_url),
            following: format!("{}/following", user_url),
            published: published_date,
            icon: if let Some(avatar) = account.avatar {
                vec![avatar]
            } else {
                Vec::default()
            },
        })
    }
}
