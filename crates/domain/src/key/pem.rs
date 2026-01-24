//! PEM public keys logic management.

use std::fmt;
use std::str::FromStr;

use der::Encode;
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use spki::der::DecodePem;

use crate::error::{DomainError, Result};
use crate::key::public_key::KeyError;

/// Value object of PEM fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemFingerprint(String);

impl PemFingerprint {
    // Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
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
