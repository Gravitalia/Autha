//! Token refresh use case implementation.

use async_trait::async_trait;
use domain::auth::factor::{FactorMethod, FactorType, VerifiedFactor};
use domain::auth::proof::AuthenticationProofBuilder;
use domain::error::DomainError;

use crate::dto::{AuthResponseDto, RefreshTokenRequestDto};
use crate::error::{ApplicationError, Result};
use crate::ports::inbound::RefreshAccessToken;
use crate::ports::outbound::{
    AccountRepository, Clock, CryptoPort, RefreshTokenManager,
    RefreshTokenRepository, TokenSigner,
};
use crate::usecases::{EXPIRES_IN, TOKEN_TYPE};

/// Token refresh use case service.
pub struct RefreshTokenUseCase {
    account_repo: Box<dyn AccountRepository>,
    refresh_token_repo: Box<dyn RefreshTokenRepository>,
    crypto: Box<dyn CryptoPort>,
    token_signer: Box<dyn TokenSigner>,
    refresh_token_manager: Box<dyn RefreshTokenManager>,
    clock: Box<dyn Clock>,
}

impl RefreshTokenUseCase {
    pub fn new(
        account_repo: Box<dyn AccountRepository>,
        refresh_token_repo: Box<dyn RefreshTokenRepository>,
        crypto: Box<dyn CryptoPort>,
        token_signer: Box<dyn TokenSigner>,
        refresh_token_manager: Box<dyn RefreshTokenManager>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            account_repo,
            refresh_token_repo,
            crypto,
            token_signer,
            refresh_token_manager,
            clock,
        }
    }
}

#[async_trait]
impl RefreshAccessToken for RefreshTokenUseCase {
    async fn execute(
        &self,
        request: RefreshTokenRequestDto,
    ) -> Result<AuthResponseDto> {
        let refresh_token =
            self.crypto.hasher().hash(request.refresh_token.as_bytes());
        let user_id = self
            .refresh_token_repo
            .find_user_id(&refresh_token)
            .await?
            .ok_or(DomainError::TokenNotFound)?;

        // Verify user still exists and is not deleted.
        let account = self
            .account_repo
            .find_by_id(&user_id)
            .await?
            .ok_or(ApplicationError::UserNotFound)?;

        if account.deleted_at.is_some() {
            return Err(ApplicationError::AccountDeleted {
                date: account.deleted_at.unwrap_or_default(),
            });
        }

        self.refresh_token_repo.revoke(&refresh_token).await?;

        let now = self.clock.now();
        let verified_factor = VerifiedFactor::new(
            FactorType::Knowledge,
            FactorMethod::Password,
            now,
        );

        let proof = AuthenticationProofBuilder::default()
            .user_id(&account.id)
            .authenticated_at(now)
            .add_factor(verified_factor)
            .build()?;

        let access_token = self.token_signer.create_access_token(&proof)?;
        let new_refresh_token = self.refresh_token_manager.generate();

        self.refresh_token_repo
            .store(
                &self.crypto.hasher().hash(new_refresh_token.as_bytes()),
                &account.id,
                request.ip_address.as_deref(),
            )
            .await?;

        Ok(AuthResponseDto {
            access_token,
            refresh_token: new_refresh_token,
            token_type: TOKEN_TYPE.to_string(),
            expires_in: EXPIRES_IN,
        })
    }
}
