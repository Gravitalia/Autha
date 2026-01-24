//! Authentication proof concepts.
//!
//! A proof represents evidence that a user has successfully authenticated.
//! This is the result of the authentication process.

use crate::auth::email::EmailHash;
use crate::auth::factor::{FactorType, TotpCode, VerifiedFactor};
use crate::auth::password::Password;
use crate::error::{DomainError, Result};
use crate::identity::id::UserId;

/// Identifier used for authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthIdentifier {
    Email(EmailHash),
    UserId(UserId),
}

/// Authentication proof.
#[derive(Debug, Clone)]
pub struct AuthenticationProof {
    user_id: UserId,
    verified_factors: Vec<VerifiedFactor>,
    authenticated_at: u64,
}

impl AuthenticationProof {
    /// Create a new authentication proof.
    pub fn new(
        user_id: UserId,
        verified_factors: Vec<VerifiedFactor>,
        authenticated_at: u64,
    ) -> Result<Self> {
        if verified_factors.is_empty() {
            return Err(DomainError::InvalidCredentials);
        }

        Ok(Self {
            user_id,
            verified_factors,
            authenticated_at,
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn verified_factors(&self) -> &[VerifiedFactor] {
        &self.verified_factors
    }

    pub fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    /// Check if a specific factor type was verified.
    pub fn has_factor_type(&self, factor_type: FactorType) -> bool {
        self.verified_factors
            .iter()
            .any(|f| f.factor_type() == factor_type)
    }
}

/// Builder for creating authentication proofs step by step.
#[derive(Debug, Default)]
pub struct AuthenticationProofBuilder {
    user_id: Option<UserId>,
    verified_factors: Vec<VerifiedFactor>,
    authenticated_at: Option<u64>,
}

impl AuthenticationProofBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn add_factor(mut self, factor: VerifiedFactor) -> Self {
        self.verified_factors.push(factor);
        self
    }

    pub fn authenticated_at(mut self, timestamp: u64) -> Self {
        self.authenticated_at = Some(timestamp);
        self
    }

    pub fn build(self) -> Result<AuthenticationProof> {
        let user_id = self.user_id.ok_or(DomainError::ValidationFailed {
            field: "user_id".into(),
            message: "user_id is required".into(),
        })?;

        let authenticated_at =
            self.authenticated_at.ok_or(DomainError::ValidationFailed {
                field: "authenticated_at".into(),
                message: "authenticated_at is required".into(),
            })?;

        AuthenticationProof::new(
            user_id,
            self.verified_factors,
            authenticated_at,
        )
    }
}

/// Represents an authentication attempt (before verification).
#[derive(Debug, Clone)]
pub struct AuthenticationAttempt {
    identifier: AuthIdentifier,
    password: Password,
    totp_code: Option<TotpCode>,
    ip: Option<String>,
}

impl AuthenticationAttempt {
    /// Create a new [`AuthenticationAttempt`].
    pub fn new(
        identifier: AuthIdentifier,
        password: Password,
        totp_code: Option<TotpCode>,
        ip: Option<String>,
    ) -> Self {
        Self {
            identifier,
            password,
            totp_code,
            ip,
        }
    }

    pub fn identifier(&self) -> &AuthIdentifier {
        &self.identifier
    }

    pub fn password(&self) -> &Password {
        &self.password
    }

    pub fn totp_code(&self) -> Option<&TotpCode> {
        self.totp_code.as_ref()
    }

    pub fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }
}
