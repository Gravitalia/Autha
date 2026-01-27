//! Authentication domain invariants.

use crate::auth::factor::FactorType;
use crate::auth::proof::AuthenticationProof;
use crate::error::{DomainError, Result};

/// Validates that TOTP is provided when the user has TOTP enabled.
pub fn validate_totp_requirement(
    has_totp_secret: bool,
    totp_code_provided: bool,
) -> Result<()> {
    if has_totp_secret && !totp_code_provided {
        return Err(DomainError::TotpRequired);
    }
    Ok(())
}

/// Validates that an authentication is not too old.
pub fn validate_auth_freshness(
    authenticated_at: u64,
    current_time: u64,
    max_age_seconds: u64,
) -> Result<()> {
    let age = current_time.saturating_sub(authenticated_at);
    if age > max_age_seconds {
        return Err(DomainError::TokenExpired);
    }
    Ok(())
}

/// Validates that sensitive operations require recent authentication.
pub fn validate_sensitive_operation(
    proof: &AuthenticationProof,
    current_time: u64,
    max_age_seconds: u64,
) -> Result<()> {
    validate_auth_freshness(
        proof.authenticated_at(),
        current_time,
        max_age_seconds,
    )?;

    if !proof.has_factor_type(FactorType::Possession) {
        return Err(DomainError::InvariantViolation);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::factor::{FactorMethod, VerifiedFactor};
    use crate::identity::id::UserId;

    fn create_proof_with_password_only<'a>(
        user_id: &'a UserId,
        timestamp: u64,
    ) -> AuthenticationProof<'a> {
        let factor = VerifiedFactor::new(
            FactorType::Knowledge,
            FactorMethod::Password,
            timestamp,
        );
        AuthenticationProof::new(user_id, vec![factor], timestamp).unwrap()
    }

    fn create_proof_with_mfa<'a>(
        user_id: &'a UserId,
        timestamp: u64,
    ) -> AuthenticationProof<'a> {
        let password_factor = VerifiedFactor::new(
            FactorType::Knowledge,
            FactorMethod::Password,
            timestamp,
        );
        let totp_factor = VerifiedFactor::new(
            FactorType::Possession,
            FactorMethod::Totp,
            timestamp,
        );
        AuthenticationProof::new(
            user_id,
            vec![password_factor, totp_factor],
            timestamp,
        )
        .unwrap()
    }

    #[test]
    fn test_validate_totp_requirement() {
        assert!(validate_totp_requirement(true, true).is_ok());

        let err = validate_totp_requirement(true, false).unwrap_err();
        assert!(matches!(err, DomainError::TotpRequired));

        assert!(validate_totp_requirement(false, true).is_ok());

        assert!(validate_totp_requirement(false, false).is_ok());
    }

    #[test]
    fn test_validate_auth_freshness() {
        assert!(validate_auth_freshness(1000, 1500, 600).is_ok());

        let err = validate_auth_freshness(1000, 2000, 600).unwrap_err();
        assert!(matches!(err, DomainError::TokenExpired));

        // Edge case: exactly at limit.
        assert!(validate_auth_freshness(1000, 1600, 600).is_ok());
    }

    #[test]
    fn test_sensitive_operation_requires_mfa() {
        let user_id = UserId::parse("user".into()).unwrap();

        let password_only = create_proof_with_password_only(&user_id, 1000);
        let result = validate_sensitive_operation(&password_only, 1100, 600);
        assert!(result.is_err());

        let mfa = create_proof_with_mfa(&user_id, 1000);
        let result = validate_sensitive_operation(&mfa, 1100, 600);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sensitive_operation_requires_freshness() {
        let user_id = UserId::parse("user".into()).unwrap();
        let mfa = create_proof_with_mfa(&user_id, 1000);

        assert!(validate_sensitive_operation(&mfa, 1100, 600).is_ok());

        // Stale.
        let result = validate_sensitive_operation(&mfa, 2000, 600);
        assert!(matches!(result.unwrap_err(), DomainError::TokenExpired));
    }
}
