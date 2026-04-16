//! Update user use case implementation.

use std::sync::Arc;

use async_trait::async_trait;
use domain::auth::factor::{TotpCode, TotpConfig, TotpSecret};
use domain::auth::password::Password;
use domain::error::DomainError;
use domain::identity::email::EmailAddress;
use domain::identity::id::UserId;
use domain::key::pem::PemPublicKey;

use crate::dto::{PublicKeyDto, TypedKeyDto, UpdateUserDto};
use crate::error::{ApplicationError, Result};
use crate::ports::inbound::UpdateUser;
use crate::ports::outbound::{AccountRepository, CryptoPort, Mailer};

/// Use case for updating user profile.
pub struct UpdateUserUseCase {
    account_repo: Arc<dyn AccountRepository>,
    crypto: Arc<dyn CryptoPort>,
    mailer: Option<Arc<dyn Mailer>>,
}

impl UpdateUserUseCase {
    pub fn new(
        account_repo: Arc<dyn AccountRepository>,
        crypto: Arc<dyn CryptoPort>,
        mailer: Option<Arc<dyn Mailer>>,
    ) -> Self {
        Self {
            account_repo,
            crypto,
            mailer,
        }
    }
}

#[async_trait]
impl UpdateUser for UpdateUserUseCase {
    async fn update(
        &self,
        user_id: &UserId,
        payload: UpdateUserDto,
    ) -> Result<Vec<String>> {
        let mut user = self
            .account_repo
            .find_by_id(user_id)
            .await?
            .ok_or(ApplicationError::UserNotFound)?;

        let mut updated_keys = Vec::new();

        if let Some(username) = payload.username {
            user.username = username;
        }

        if let Some(summary) = payload.summary {
            user.summary = Some(summary);
        }

        if let (Some(secret_str), Some(password_str), Some(code_str)) =
            (&payload.totp_secret, &payload.password, &payload.totp_code)
        {
            let pwd = Password::new(password_str)?;
            self.crypto
                .password_hasher()
                .verify(&pwd, &user.password_hash)?;

            let secret = TotpSecret::new(secret_str)?;
            let code = TotpCode::six_digits(code_str)?;

            if self.crypto.totp_generator().verify(
                &code,
                &secret,
                &TotpConfig::default(),
            )? {
                let encrypted_secret = self
                    .crypto
                    .symmetric_encryption()
                    .encrypt_to_hex(secret.as_str().as_bytes())?;
                user.totp_secret = Some(encrypted_secret);
            } else {
                return Err(DomainError::InvalidTotpCode.into());
            }
        } else if payload.totp_secret.is_some() || payload.totp_code.is_some()
        {
            return Err(DomainError::ValidationFailed {
                field: "totp".into(),
                message: "Missing required fields for TOTP update".into(),
            }
            .into());
        }

        if let (Some(new_email), Some(password_str)) =
            (&payload.email, &payload.password)
        {
            let pwd = Password::new(password_str)?;
            self.crypto
                .password_hasher()
                .verify(&pwd, &user.password_hash)?;

            let email = EmailAddress::parse(new_email)?;
            let email_hash = self.crypto.hasher().hash(email.as_bytes());
            let email_cipher = self
                .crypto
                .symmetric_encryption()
                .encrypt_to_hex(email.as_bytes())?;

            user.email_hash = domain::auth::email::EmailHash::new(email_hash);
            user.email_cipher = email_cipher;

            if let Some(mailer) = &self.mailer {
                mailer
                    .send_update_notification(
                        &email,
                        &user.locale,
                        &user.username,
                    )
                    .await?;
            }
        }

        if let (Some(new_password_str), Some(current_password_str)) =
            (&payload.new_password, &payload.password)
        {
            let pwd = Password::new(current_password_str)?;
            self.crypto
                .password_hasher()
                .verify(&pwd, &user.password_hash)?;

            let new_password = Password::new(new_password_str)?;
            let new_password_hash =
                self.crypto.password_hasher().hash(&new_password)?;

            user.password_hash = new_password_hash;

            if let Some(mailer) = &self.mailer {
                let decrypted_email_bytes = self
                    .crypto
                    .symmetric_encryption()
                    .decrypt_from_hex(&user.email_cipher)?;
                let decrypted_email = String::from_utf8(decrypted_email_bytes)
                    .map_err(|_| DomainError::InvariantViolation)?;
                let email = EmailAddress::parse(&decrypted_email)?;

                mailer
                    .send_update_notification(
                        &email,
                        &user.locale,
                        &user.username,
                    )
                    .await?;
            }
        }

        if let Some(keys) = payload.public_keys {
            match keys {
                TypedKeyDto::One(key) => {
                    let pem = PemPublicKey::parse(key.clone())?;
                    let id = pem.fingerprint()?;

                    user.public_keys.push(PublicKeyDto {
                        id: id.clone(),
                        owner: user_id.to_string(),
                        public_key_pem: key,
                        created_at: chrono::Utc::now()
                            .format("%Y-%m-%d")
                            .to_string(),
                    });
                    updated_keys.push(id.as_str().to_string());
                },
                TypedKeyDto::Multiple(keys) => {
                    for key in keys {
                        let pem = PemPublicKey::parse(key.clone())?;
                        let id = pem.fingerprint()?;

                        user.public_keys.push(PublicKeyDto {
                            id: id.clone(),
                            owner: user_id.to_string(),
                            public_key_pem: key,
                            created_at: chrono::Utc::now()
                                .format("%Y-%m-%d")
                                .to_string(),
                        });
                        updated_keys.push(id.as_str().to_string());
                    }
                },
                TypedKeyDto::Remove(key_id_to_remove) => {
                    user.public_keys
                        .retain(|k| k.id.as_i32() != key_id_to_remove);
                },
            }
        }

        self.account_repo.update(&user).await?;

        Ok(updated_keys)
    }
}
