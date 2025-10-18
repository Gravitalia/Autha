//! Manage json web tokens.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::error::Result;

const DEFAULT_AUDIENCE: &str = "account.gravitalia.com";
const EXPIRATION_TIME: u64 = 1000 * 60 * 15; // 15 minutes.

/// Pieces of information asserted on a JWT.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
}

/// Manage JWT tokens.
#[derive(Clone, Debug)]
pub struct TokenManager {
    algorithm: Algorithm,
    public_key: Option<DecodingKey>,
    private_key: EncodingKey,
    name: String,
    audience: String,
    // key_id: Option<String>,
    // jku: Option<String>,
}

impl TokenManager {
    /// Create a new [`TokenManager`] instance.
    pub fn new(name: &str, public_key_pem: &str, private_key_pem: &str) -> Result<Self> {
        let public_key = if public_key_pem.is_empty() {
            None
        } else {
            Some(DecodingKey::from_ec_pem(public_key_pem.as_bytes())?)
        };
        let private_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())?;

        Ok(Self {
            algorithm: Algorithm::ES384,
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
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let header = Header::new(self.algorithm);
        let claims = Claims {
            aud: self.audience.clone(),
            exp: time + EXPIRATION_TIME,
            iat: time,
            iss: self.name.clone(),
            sub: user_id.to_owned(),
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

        let validation = Validation::new(self.algorithm);
        Ok(decode::<Claims>(token, public_key, &validation)?.claims)
    }
}
