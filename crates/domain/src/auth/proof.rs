//! Authentication proof concepts.
//!
//! A proof represents evidence that a user has successfully authenticated.
//! This is the result of the authentication process.

use crate::auth::email::EmailHash;
use crate::auth::factor::{FactorType, TotpCode, VerifiedFactor};
use crate::auth::password::Password;
use crate::error::{DomainError, Result};
use crate::identity::id::UserId;

/// The identifier provided by the user to initiate the authentication process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthIdentifier {
    Email(EmailHash),
    UserId(UserId),
}

/// Validated evidence of a successful authentication session.
#[derive(Debug, Clone)]
pub struct AuthenticationProof<'a> {
    user_id: &'a UserId,
    verified_factors: Vec<VerifiedFactor>,
    authenticated_at: u64,
}

impl<'a> AuthenticationProof<'a> {
    /// Creates a new [`AuthenticationProof`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidCredentials`] if the list of verified
    /// factors is empty, as a proof must contain at least one successful
    /// authentication factor.
    pub fn new(
        user_id: &'a UserId,
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

    /// Returns the [`UserId`] associated with this proof.
    #[inline]
    pub fn user_id(&self) -> &UserId {
        self.user_id
    }

    /// Returns a slice of all [`VerifiedFactor`]s used in this proof.
    #[inline]
    pub fn verified_factors(&self) -> &[VerifiedFactor] {
        &self.verified_factors
    }

    /// Returns the timestamp (in seconds) when the authentication occurred.
    #[inline]
    pub fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    /// Returns `true` if a factor of the specified [`FactorType`] is present
    /// in this proof.
    pub fn has_factor_type(&self, factor_type: FactorType) -> bool {
        self.verified_factors
            .iter()
            .any(|f| f.factor_type() == factor_type)
    }
}

/// Builder for creating authentication proofs step by step.
#[derive(Debug, Default)]
pub struct AuthenticationProofBuilder<'a> {
    user_id: Option<&'a UserId>,
    verified_factors: Vec<VerifiedFactor>,
    authenticated_at: Option<u64>,
}

impl<'a> AuthenticationProofBuilder<'a> {
    /// Sets the [`UserId`] for the proof.
    pub fn user_id(mut self, user_id: &'a UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Adds a single [`VerifiedFactor`] to the proof.
    pub fn add_factor(mut self, factor: VerifiedFactor) -> Self {
        self.verified_factors.push(factor);
        self
    }

    /// Moves all factors from the provided vector into the builder.
    pub fn add_factors(mut self, mut factors: Vec<VerifiedFactor>) -> Self {
        self.verified_factors.reserve(factors.len());
        self.verified_factors.append(&mut factors);
        self
    }

    /// Sets the authentication timestamp.
    pub fn authenticated_at(mut self, timestamp: u64) -> Self {
        self.authenticated_at = Some(timestamp);
        self
    }

    /// Attempts to build the [`AuthenticationProof`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::ValidationFailed`] if `user_id` or
    /// `authenticated_at` are missing, and [`DomainError::InvalidCredentials`]
    /// if no verified factors were added.
    pub fn build(self) -> Result<AuthenticationProof<'a>> {
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

/// Represents the data provided during an authentication attempt.
#[derive(Debug, Clone)]
pub struct AuthenticationAttempt {
    identifier: AuthIdentifier,
    password: Password,
    totp_code: Option<TotpCode>,
    ip: Option<String>,
}

impl AuthenticationAttempt {
    /// Creates a new [`AuthenticationAttempt`] with the provided credentials.
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

    /// Returns the identifier (email or ID) used for this attempt.
    #[inline]
    pub fn identifier(&self) -> &AuthIdentifier {
        &self.identifier
    }

    /// Returns the [`Password`] provided by the user.
    #[inline]
    pub fn password(&self) -> &Password {
        &self.password
    }

    /// Returns the optional [`TotpCode`] if one was provided.
    #[inline]
    pub fn totp_code(&self) -> Option<&TotpCode> {
        self.totp_code.as_ref()
    }

    #[inline]
    pub fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }
}
