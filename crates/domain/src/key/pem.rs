//! PEM public keys logic management.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use spki::der::{DecodePem, Encode};

use crate::error::{DomainError, Result};
use crate::key::public_key::KeyError;

/// Value object of PEM fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemFingerprint(String);

impl PemFingerprint {
    /// Create a new [`PemFingerprint`].
    pub fn new(fingerprint: impl ToString) -> Self {
        PemFingerprint(fingerprint.to_string())
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PemFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Value object of a valid public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemPublicKey {
    raw_pem: String,
    spki: SubjectPublicKeyInfoOwned,
}

impl PemPublicKey {
    /// Converts a [`String`] into a valid [`PemPublicKey`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string is not a valid RSA or ECDSA PEM
    /// public key.
    pub fn parse(pem: String) -> Result<Self> {
        let spki = SubjectPublicKeyInfoOwned::from_pem(&pem)
            .map_err(|_| KeyError::InvalidFormat)?;

        Ok(Self { raw_pem: pem, spki })
    }

    /// Calculate SPKI fingerprint as defined on RFC7093.
    ///
    /// Since fingerprint is defined in RFC, it is considered as business logic
    /// for DDD.
    pub fn fingerprint(&self) -> Result<PemFingerprint> {
        let der = self.spki.to_der().map_err(|_| DomainError::Der)?;
        let mut hasher = Sha256::new();
        hasher.update(der);
        Ok(PemFingerprint(hex::encode(&hasher.finalize()[..20])))
    }

    /// Returns the decoded SPKI structure of raw key.
    pub fn spki(&self) -> &SubjectPublicKeyInfoOwned {
        &self.spki
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.raw_pem
    }
}

impl FromStr for PemPublicKey {
    type Err = DomainError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s.to_string())
    }
}

impl fmt::Display for PemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw_pem)
    }
}

impl AsRef<str> for PemPublicKey {
    fn as_ref(&self) -> &str {
        &self.raw_pem
    }
}

impl TryFrom<String> for PemPublicKey {
    type Error = DomainError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RSA_PUB_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHgX8gieCwHlUYtM3gcq9h/sDaqg
Uhj88N4b2UJdV3CRZVD3jjL2waNIAuat7VMM/daNN0x34ixsQ8GxaBcMooG6nOAq
rfVXEFg2JmRE/rNm2RfhVp+fMjeHQNq6vLrEVg4r84vzUevkSVMvcZ0LxYtGMzVe
1ayeq+eHEjsXkdKBAgMBAAE=
-----END PUBLIC KEY-----";

    #[test]
    fn test_parse_valid_pem() {
        let result = PemPublicKey::parse(TEST_RSA_PUB_KEY.to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_pem() {
        let result = PemPublicKey::parse(
            "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----"
                .to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_fingerprint_consistency() {
        let key = PemPublicKey::parse(TEST_RSA_PUB_KEY.to_string()).unwrap();
        let fp1 = key.fingerprint().unwrap();
        let fp2 = key.fingerprint().unwrap();

        assert_eq!(fp1, fp2);
        assert_eq!(fp1.as_str().len(), 40);
        assert!(fp1.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
