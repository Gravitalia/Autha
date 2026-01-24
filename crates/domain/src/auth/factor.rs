//! Multi-factor (TOTP) authentication abstractions.

use crate::error::{DomainError, Result};

/// Represents a TOTP (Time-based One-Time Password) configuration.
/// This is a pure value object with no behavior requiring external
/// dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpConfig {
    /// Time step in seconds (usually 30).
    time_step: u64,
    /// Number of digits in the code (usually 6).
    digits: u8,
    /// Algorithm identifier (e.g., "SHA1", "SHA256").
    algorithm: TotpAlgorithm,
}

impl TotpConfig {
    pub const DEFAULT_DIGITS: u8 = 6;
    /// Default TOTP configuration as per RFC 6238.
    pub const DEFAULT_TIME_STEP: u64 = 30;

    /// Create a new TOTP configuration with validation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `time_step` is inferior or equal to
    /// zero or if `digits` is not contained between 4 and 8.
    pub fn new(
        time_step: u64,
        digits: u8,
        algorithm: TotpAlgorithm,
    ) -> Result<Self> {
        if time_step == 0 {
            return Err(DomainError::ValidationFailed {
                field: "time_step".into(),
                message: "time step must be greater than 0".into(),
            });
        }

        if !(4..=8).contains(&digits) {
            return Err(DomainError::ValidationFailed {
                field: "digits".into(),
                message: "digits must be between 4 and 8".into(),
            });
        }

        Ok(Self {
            time_step,
            digits,
            algorithm,
        })
    }

    /// Create default TOTP configuration (30s, 6 digits, SHA1).
    pub fn default_config() -> Self {
        Self {
            time_step: Self::DEFAULT_TIME_STEP,
            digits: Self::DEFAULT_DIGITS,
            algorithm: TotpAlgorithm::Sha1,
        }
    }

    pub fn time_step(&self) -> u64 {
        self.time_step
    }

    pub fn digits(&self) -> u8 {
        self.digits
    }

    pub fn algorithm(&self) -> &TotpAlgorithm {
        &self.algorithm
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Supported TOTP algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// TOTP code value object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    value: String,
    digits: u8,
}

impl TotpCode {
    /// Create a new TOTP code with validation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `code` is not `expected_digits` length or decimal.
    pub fn new(code: impl Into<String>, expected_digits: u8) -> Result<Self> {
        let value = code.into();

        if value.len() != expected_digits as usize {
            return Err(DomainError::ValidationFailed {
                field: "totp_code".into(),
                message: format!("TOTP code must be {expected_digits} digits"),
            });
        }

        if !value.chars().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::ValidationFailed {
                field: "totp_code".into(),
                message: "TOTP code must contain only digits".into(),
            });
        }

        Ok(Self {
            value,
            digits: expected_digits,
        })
    }

    /// Create with default 6 digits.
    pub fn six_digits(code: impl Into<String>) -> Result<Self> {
        Self::new(code, 6)
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn digits(&self) -> u8 {
        self.digits
    }
}

/// TOTP secret value object.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret {
    /// Base32-encoded secret (RFC 4648).
    encoded: String,
}

impl TotpSecret {
    /// Create a new TOTP secret with base32 validation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if string is not base32.
    pub fn new(encoded: impl Into<String>) -> Result<Self> {
        let encoded = encoded.into();

        // Validate base32 format (RFC 4648).
        if !Self::is_valid_base32(&encoded) {
            return Err(DomainError::InvalidTotpSecret);
        }

        Ok(Self { encoded })
    }

    #[inline]
    fn is_valid_base32(s: &str) -> bool {
        const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        if s.is_empty() {
            return false;
        }

        s.bytes()
            .all(|b| BASE32_CHARS.contains(&b.to_ascii_uppercase()))
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Consume and return the inner value.
    #[inline]
    pub fn into_inner(self) -> String {
        self.encoded
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecret")
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorType {
    Knowledge,
    Possession,
    Inherence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFactor {
    factor_type: FactorType,
    method: FactorMethod,
    verified_at: u64, // Unix timestamp.
}

impl VerifiedFactor {
    /// Create a new [`VerifiedFactor`].
    pub fn new(
        factor_type: FactorType,
        method: FactorMethod,
        verified_at: u64,
    ) -> Self {
        Self {
            factor_type,
            method,
            verified_at,
        }
    }

    pub fn factor_type(&self) -> FactorType {
        self.factor_type
    }

    pub fn method(&self) -> &FactorMethod {
        &self.method
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

/// Specific method used for authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactorMethod {
    Password,
    Totp,
    WebAuthn { credential_id: String },
    RecoveryCode,
}
