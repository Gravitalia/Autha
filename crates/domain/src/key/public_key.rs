//! Builder for public key.

use chrono::{DateTime, Utc};

use crate::error::Result;
use crate::identity::id::UserId;
use crate::key::pem::{PemFingerprint, PemPublicKey};

/// Logical errors related to public keys.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key id cannot be empty")]
    EmptyId,
    #[error("pem format is invalid")]
    InvalidPem,
    #[error("pem is not pkcs1 nor pkcs8")]
    InvalidFormat,
}

/// Public key linked to a [`User`].
#[derive(Clone, Debug, PartialEq)]
pub struct Key {
    pub id: PemFingerprint,
    pub owner: UserId,
    pub public_key_pem: PemPublicKey,
    pub created_at: DateTime<Utc>,
}

impl Key {
    /// Create a new [`Key`].
    pub fn new(
        owner: UserId,
        pem: PemPublicKey,
        created_at: DateTime<Utc>,
    ) -> Result<Self> {
        let id = pem.fingerprint()?;
        Ok(Self {
            id,
            owner,
            public_key_pem: pem,
            created_at,
        })
    }
}
