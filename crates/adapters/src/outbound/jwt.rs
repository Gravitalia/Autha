//! JWT signing and verification using ES256 (ECDSA P-256).

use application::error::{ApplicationError, Result, ToInternal};
use application::ports::outbound::{
    SecureRandom, TokenClaims, TokenSigner as ImplTokenSigner,
};
use domain::auth::proof::AuthenticationProof;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use serde::{Deserialize, Serialize};

use crate::outbound::crypto::random::OsRngRandom;

const JTI_LENGTH: usize = 12;
const DEFAULT_AUDIENCE: &str = "account.gravitalia.com";
const ACCESS_TOKEN_EXPIRATION: u64 = 900; // 15 minutes.
pub static SCOPES: [&str; 3] =
    ["read:account", "write:account", "write:public_keys"];

/// JWT signer.
pub struct TokenSigner {
    algorithm: Algorithm,
    kid: String,
    issuer: String,
    audience: String,
    encoding_key: EncodingKey,
    decoding_key: Option<DecodingKey>,
}

impl TokenSigner {
    /// Create a new [`TokenSigner`].
    pub fn new(
        kid: impl Into<String>,
        issuer: impl Into<String>,
        public_key_pem: &str,
        private_key_pem: &str,
    ) -> Result<Self> {
        let encoding_key =
            EncodingKey::from_ec_pem(private_key_pem.as_bytes()).catch()?;

        let decoding_key = if !public_key_pem.is_empty() {
            Some(DecodingKey::from_ec_pem(public_key_pem.as_bytes()).catch()?)
        } else {
            None
        };

        Ok(Self {
            algorithm: Algorithm::ES256,
            kid: kid.into(),
            issuer: issuer.into(),
            audience: DEFAULT_AUDIENCE.to_string(),
            encoding_key,
            decoding_key,
        })
    }

    /// Set `audience` field on JWT.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
    iat: u64,
    jti: String,
    scope: String,
}

impl ImplTokenSigner for TokenSigner {
    fn create_access_token(
        &self,
        proof: &AuthenticationProof,
    ) -> Result<String> {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());

        let claims = JwtClaims {
            sub: proof.user_id().to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp: proof.authenticated_at() + ACCESS_TOKEN_EXPIRATION,
            iat: proof.authenticated_at(),
            jti: OsRngRandom::new().random_string(JTI_LENGTH)?,
            scope: SCOPES.join(" "),
        };

        encode(&header, &claims, &self.encoding_key).catch()
    }

    fn verify_token(&self, token: &str) -> Result<TokenClaims> {
        let decoding_key = self
            .decoding_key
            .as_ref()
            .ok_or_else(|| ApplicationError::Unknown)?;

        let mut validation = Validation::new(self.algorithm);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);

        let token_data =
            decode::<JwtClaims>(token, decoding_key, &validation).catch()?;

        Ok(TokenClaims {
            sub: token_data.claims.sub,
            iss: token_data.claims.iss,
            aud: token_data.claims.aud,
            exp: token_data.claims.exp,
            iat: token_data.claims.iat,
            jti: token_data.claims.jti,
            scope: token_data.claims.scope,
        })
    }

    fn key_id(&self) -> &str {
        &self.kid
    }
}
