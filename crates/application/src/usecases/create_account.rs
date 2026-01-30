//! Account creation use case implementation.

use async_trait::async_trait;
use domain::auth::email::EmailHash;
use domain::auth::factor::{FactorMethod, FactorType, VerifiedFactor};
use domain::auth::proof::AuthenticationProofBuilder;
use domain::identity::account::DEFAULT_LOCALE;

use crate::dto::{AccountDto, AuthResponseDto, CreateAccountRequestDto};
use crate::error::Result;
use crate::ports::inbound::CreateAccount;
use crate::ports::outbound::{
    AccountRepository, Clock, CryptoPort, Mailer, RefreshTokenRepository,
    TelemetryPort, Token,
};
use crate::usecases::{EXPIRES_IN, TOKEN_TYPE};

/// Account creation use case service.
pub struct CreateAccountUseCase {
    account_repo: Box<dyn AccountRepository>,
    refresh_token_repo: Box<dyn RefreshTokenRepository>,
    crypto: Box<dyn CryptoPort>,
    mailer: Box<dyn Mailer>,
    token: Box<dyn Token>,
    telemetry: Box<dyn TelemetryPort>,
    clock: Box<dyn Clock>,
}

impl CreateAccountUseCase {
    pub fn new(
        account_repo: Box<dyn AccountRepository>,
        refresh_token_repo: Box<dyn RefreshTokenRepository>,
        crypto: Box<dyn CryptoPort>,
        mailer: Box<dyn Mailer>,
        token: Box<dyn Token>,
        telemetry: Box<dyn TelemetryPort>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            account_repo,
            refresh_token_repo,
            crypto,
            mailer,
            token,
            telemetry,
            clock,
        }
    }
}

#[async_trait]
impl CreateAccount for CreateAccountUseCase {
    async fn execute(
        &self,
        request: CreateAccountRequestDto,
    ) -> Result<AuthResponseDto> {
        let password_hash =
            self.crypto.password_hasher().hash(&request.password)?;

        let email_bytes = request.email.as_ref().as_bytes();
        let email_hash =
            EmailHash::new(self.crypto.hasher().hash(email_bytes));
        let email_cipher = self
            .crypto
            .symmetric_encryption()
            .encrypt_to_hex(email_bytes)?;

        let locale =
            request.locale.unwrap_or_else(|| DEFAULT_LOCALE.to_string());

        let now = self.clock.now();
        let account = AccountDto {
            username: request.user_id.to_string(),
            id: request.user_id,
            email_hash,
            email_cipher,
            password_hash,
            totp_secret: None,
            locale: locale.clone(),
            summary: None,
            avatar: None,
            flags: 0,
            created_at: now,
            deleted_at: None,
            public_keys: Vec::new(),
        };

        self.account_repo.create(&account).await?;

        // Later, we should handle error with retries and DLQ.
        let _ = self
            .mailer
            .send_welcome(&request.email, &locale, &account.username)
            .await;

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

        let access_token = self.token.signer().create_access_token(&proof)?;
        let refresh_token = self.token.refresh_token().generate();

        self.refresh_token_repo
            .store(
                &self.crypto.hasher().hash(refresh_token.as_bytes()),
                &account.id,
                request.ip_address.as_deref(),
            )
            .await?;

        self.telemetry.record_account_created(account.id.as_str());

        Ok(AuthResponseDto {
            access_token,
            refresh_token,
            token_type: TOKEN_TYPE.to_string(),
            expires_in: EXPIRES_IN,
        })
    }
}
