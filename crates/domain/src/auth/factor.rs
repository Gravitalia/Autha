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

        Self::validate(&value, expected_digits)?;

        Ok(Self {
            value,
            digits: expected_digits,
        })
    }

    fn validate(value: &str, expected_digits: u8) -> Result<()> {
        if value.len() != expected_digits as usize {
            // On masque le format! à Kani pour éviter la boucle infinie memcmp
            #[cfg(not(kani))]
            let message =
                format!("TOTP code must be {expected_digits} digits");

            #[cfg(kani)]
            let message = String::from("invalid length");

            return Err(DomainError::ValidationFailed {
                field: "totp_code".into(),
                message,
            });
        }

        if !(4..=8).contains(&expected_digits) {
            return Err(DomainError::ValidationFailed {
                field: "digits".into(),
                message: "digits must be between 4 and 8".into(),
            });
        }

        if !value.as_bytes().iter().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::ValidationFailed {
                field: "totp_code".into(),
                message: "TOTP code must contain only digits".into(),
            });
        }

        Ok(())
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
        let bytes = s.as_bytes();
        let len = bytes.len();

        if len == 0 {
            return false;
        }

        let mut padding_count = 0;
        let mut found_padding = false;

        for &b in bytes.iter() {
            let c = b.to_ascii_uppercase();

            if c == b'=' {
                found_padding = true;
                padding_count += 1;
            } else {
                if found_padding {
                    return false;
                }

                if !matches!(c, b'A'..=b'Z' | b'2'..=b'7') {
                    return false;
                }
            }
        }

        if found_padding {
            if !len.is_multiple_of(8) {
                return false;
            }
            matches!(padding_count, 0 | 1 | 3 | 4 | 6)
        } else {
            !matches!(len % 8, 1 | 3 | 6)
        }
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

    /// Returns the category of this factor.
    pub fn factor_type(&self) -> FactorType {
        self.factor_type
    }

    /// Returns the specific method used.
    pub fn method(&self) -> &FactorMethod {
        &self.method
    }

    /// Returns the Unix timestamp of when this factor was verified.
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

#[cfg(kani)]
mod proof {
    use super::*;

    #[kani::proof]
    #[kani::unwind(18)]
    fn prove_base32_validation_robustness() {
        let bytes: [u8; 16] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 16);
        let slice = match len {
            0 => &bytes[..0],
            1 => &bytes[..1],
            2 => &bytes[..2],
            3 => &bytes[..3],
            4 => &bytes[..4],
            5 => &bytes[..5],
            6 => &bytes[..6],
            7 => &bytes[..7],
            8 => &bytes[..8],
            9 => &bytes[..9],
            10 => &bytes[..10],
            11 => &bytes[..11],
            12 => &bytes[..12],
            13 => &bytes[..13],
            14 => &bytes[..14],
            15 => &bytes[..15],
            16 => &bytes[..16],
            _ => unreachable!(),
        };

        if let Ok(s) = std::str::from_utf8(slice) {
            let is_valid = TotpSecret::is_valid_base32(s);

            if is_valid {
                assert!(!s.is_empty());
                if s.contains('=') {
                    assert!(s.len() % 8 == 0);
                }
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(12)]
    fn prove_totp_code_invariants() {
        let bytes: [u8; 10] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 10);

        // Même technique ici
        let slice = match len {
            0 => &bytes[..0],
            1 => &bytes[..1],
            2 => &bytes[..2],
            3 => &bytes[..3],
            4 => &bytes[..4],
            5 => &bytes[..5],
            6 => &bytes[..6],
            7 => &bytes[..7],
            8 => &bytes[..8],
            9 => &bytes[..9],
            10 => &bytes[..10],
            _ => unreachable!(),
        };

        if let Ok(s) = std::str::from_utf8(slice) {
            let expected_digits: u8 = kani::any();

            match TotpCode::validate(s, expected_digits) {
                Ok(_) => {
                    assert!((4..=8).contains(&expected_digits));
                    assert_eq!(s.len(), expected_digits as usize);
                    assert!(s.as_bytes().iter().all(|c| c.is_ascii_digit()));
                },
                Err(_) => {},
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(12)]
    fn prove_totp_config_validation() {
        let time_step: u64 = kani::any();
        let digits: u8 = kani::any();
        let algo = TotpAlgorithm::Sha1;

        match TotpConfig::new(time_step, digits, algo) {
            Ok(config) => {
                assert!(config.time_step() > 0);
                assert!((4..=8).contains(&config.digits()));
            },
            Err(DomainError::ValidationFailed { field, .. }) => {
                let is_invalid_time =
                    time_step == 0 && field.as_str() == "time_step";
                let is_invalid_digits =
                    !(4..=8).contains(&digits) && field.as_str() == "digits";

                assert!(is_invalid_time || is_invalid_digits);
            },
            _ => unreachable!(),
        }
    }
}
