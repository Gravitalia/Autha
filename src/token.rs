//! Manage json web tokens.

use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::Result;

const DEFAULT_AUDIENCE: &str = "account.gravitalia.com";
pub const DEFAULT_KID: &str = "0";
const JTI_LENGTH: usize = 12;
pub const EXPIRATION_TIME: u64 = 60 * 15; // 15 minutes in seconds.
pub static SCOPES: LazyLock<Vec<String>> = LazyLock::new(|| {
    vec![
        "read:account".to_string(),
        "write:account".to_string(),
        "write:public_keys".to_string(),
    ]
});

/// Pieces of information asserted on a JWT.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Recipients that the JWT is intended for.
    pub aud: String,
    /// Identifies the expiration time on  or after which the JWT must not be
    /// accepted for processing.
    pub exp: u64,
    /// Identifies the time at which the JWT was issued.
    #[serde(rename = "iat")]
    pub iat: u64,
    /// Identifies the organization that issued the JWT.
    pub iss: String,
    /// User ID.
    pub sub: String,
    /// JWT ID.
    pub jti: String,
    /// Permissions. Splitted by a space.
    pub scope: String,
}

/// Manage JWT tokens.
#[derive(Clone, Debug)]
pub struct TokenManager {
    algorithm: Algorithm,
    kid: String,
    public_key: Option<DecodingKey>,
    private_key: EncodingKey,
    name: String,
    audience: String,
    // key_id: Option<String>,
    // jku: Option<String>,
}

impl TokenManager {
    /// Create a new [`TokenManager`] instance.
    pub fn new(
        name: &str,
        kid: Option<String>,
        public_key_pem: &str,
        private_key_pem: &str,
    ) -> Result<Self> {
        let public_key = if public_key_pem.is_empty() {
            None
        } else {
            Some(DecodingKey::from_ec_pem(public_key_pem.as_bytes())?)
        };
        let private_key =
            EncodingKey::from_ec_pem(private_key_pem.as_bytes())?;

        Ok(Self {
            algorithm: Algorithm::ES256,
            kid: kid.unwrap_or(DEFAULT_KID.to_string()),
            public_key,
            private_key,
            name: name.to_owned(),
            audience: DEFAULT_AUDIENCE.to_string(),
        })
    }

    /// Set `audience` field on JWT.
    pub fn audience(&mut self, audience: &str) {
        self.audience = audience.to_owned();
    }

    /// Create a new [`jsonwebtoken`].
    pub fn create(&self, user_id: &str) -> Result<String> {
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let jti = Alphanumeric.sample_string(&mut OsRng, JTI_LENGTH);
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        let claims = Claims {
            aud: self.audience.clone(),
            exp: time + EXPIRATION_TIME,
            iat: time,
            iss: self.name.clone(),
            sub: user_id.to_owned(),
            jti,
            scope: SCOPES.join(" "),
        };

        Ok(encode(&header, &claims, &self.private_key)?)
    }

    /// Decode and check a token.
    pub fn decode(&self, token: &str) -> Result<Claims> {
        let Some(public_key) = &self.public_key else {
            return Err(crate::error::ServerError::Key(
                crate::crypto::KeyError::UnknownFormat,
            ));
        };

        let mut validation = Validation::new(self.algorithm);
        validation.aud = Some(HashSet::from_iter([self.audience.clone()]));
        Ok(decode::<Claims>(token, public_key, &validation)?.claims)
    }
}
