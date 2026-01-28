//! Authentication use case implementation.

use async_trait::async_trait;
use domain::auth::email::EmailHash;
use domain::auth::factor::{
    FactorMethod, FactorType, TotpCode, TotpConfig, TotpSecret, VerifiedFactor,
};
use domain::auth::invariants::validate_totp_requirement;
use domain::auth::password::Password;
use domain::auth::proof::AuthenticationProofBuilder;
use domain::error::DomainError;
use domain::identity::id::UserId;

use crate::dto::{AuthRequestDto, AuthResponseDto};
use crate::error::{ApplicationError, Result};
use crate::ports::inbound::Authenticate;
use crate::ports::outbound::{
    AccountRepository, Clock, CryptoPort, RefreshTokenManager,
    RefreshTokenRepository, TelemetryPort, TokenSigner,
};

const TOKEN_TYPE: &str = "Bearer";
const EXPIRES_IN: u64 = 900; // 15 minutes.

/// Authentication use case service.
pub struct AuthenticateUseCase {
    account_repo: Box<dyn AccountRepository>,
    refresh_token_repo: Box<dyn RefreshTokenRepository>,
    crypto: Box<dyn CryptoPort>,
    token_signer: Box<dyn TokenSigner>,
    refresh_token_manager: Box<dyn RefreshTokenManager>,
    telemetry: Box<dyn TelemetryPort>,
    clock: Box<dyn Clock>,
}

impl AuthenticateUseCase {
    pub fn new(
        account_repo: Box<dyn AccountRepository>,
        refresh_token_repo: Box<dyn RefreshTokenRepository>,
        crypto: Box<dyn CryptoPort>,
        token_signer: Box<dyn TokenSigner>,
        refresh_token_manager: Box<dyn RefreshTokenManager>,
        telemetry: Box<dyn TelemetryPort>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            account_repo,
            refresh_token_repo,
            crypto,
            token_signer,
            refresh_token_manager,
            telemetry,
            clock,
        }
    }
}

#[async_trait]
impl Authenticate for AuthenticateUseCase {
    async fn execute(
        &self,
        request: AuthRequestDto,
    ) -> Result<AuthResponseDto> {
        let password = Password::new(&request.password)?;

        let account = match (&request.email, request.user_id) {
            (Some(email), None) => {
                let email_hash =
                    self.crypto.hasher().hash(email.as_str().as_bytes());
                self.account_repo
                    .find_by_email_hash(EmailHash::new(email_hash))
                    .await?
                    .ok_or(ApplicationError::UserNotFound)?
            },
            (None, Some(user_id)) => {
                // In fact it will check on directory such as LDAP.
                self.account_repo
                    .find_by_id(UserId::parse(user_id)?)
                    .await?
                    .ok_or(ApplicationError::UserNotFound)?
            },
            (Some(_), Some(_)) => {
                self.telemetry.record_auth_failure("ambiguous_identifier");
                return Err(DomainError::ValidationFailed {
                    field: "identifier".into(),
                    message: "email and user_id are mutually exclusive".into(),
                }
                .into());
            },
            _ => {
                self.telemetry.record_auth_failure("missing_identifier");
                return Err(DomainError::ValidationFailed {
                    field: "identifier".into(),
                    message: "email or user_id is required".into(),
                }
                .into());
            },
        };

        if account.deleted_at.is_some() {
            self.telemetry.record_auth_failure("account_deleted");
            return Err(ApplicationError::AccountDeleted {
                date: account.deleted_at.unwrap_or_default(),
            });
        }

        self.crypto
            .password_hasher()
            .verify(&password, &account.password_hash)?;

        let now = self.clock.now();
        let mut verified_factors = vec![VerifiedFactor::new(
            FactorType::Knowledge,
            FactorMethod::Password,
            now,
        )];

        let has_totp = account.totp_secret.is_some();
        let totp_provided = request.totp_code.is_some();

        validate_totp_requirement(has_totp, totp_provided)?;

        if let (Some(encrypted_secret), Some(code)) =
            (&account.totp_secret, &request.totp_code)
        {
            let secret_bytes = self
                .crypto
                .symmetric_encryption()
                .decrypt_from_hex(encrypted_secret)?;
            let secret_str = String::from_utf8(secret_bytes)
                .map_err(|_| DomainError::InvalidTotpSecret)?;

            let secret = TotpSecret::new(secret_str)?;
            let totp_code = TotpCode::six_digits(code)?;

            if !self.crypto.totp_generator().verify(
                &totp_code,
                &secret,
                &TotpConfig::default(),
            )? {
                self.telemetry.record_auth_failure("invalid_totp");
                return Err(DomainError::InvalidTotpCode.into());
            }

            verified_factors.push(VerifiedFactor::new(
                FactorType::Possession,
                FactorMethod::Totp,
                now,
            ));
        }

        let proof = AuthenticationProofBuilder::default()
            .user_id(&account.id)
            .authenticated_at(now)
            .add_factors(verified_factors)
            .build()?;

        let access_token = self.token_signer.create_access_token(&proof)?;
        let refresh_token = self.refresh_token_manager.generate();

        // This API hash token on database.
        self.refresh_token_repo
            .store(&refresh_token, &account.id, request.ip_address.as_deref())
            .await?;

        self.telemetry
            .record_auth_success(account.id.as_str(), "password");

        Ok(AuthResponseDto {
            access_token,
            refresh_token,
            token_type: TOKEN_TYPE.to_string(),
            expires_in: EXPIRES_IN,
        })
    }
}
