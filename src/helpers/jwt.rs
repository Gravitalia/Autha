use anyhow::Result;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub scope: Vec<String>,
    pub exp: u64,
    iss: String,
    iat: u64,
}

/// Create a JWT token
pub fn create_jwt(user_id: String, scope: Vec<String>) -> String {
    let private_key = EncodingKey::from_rsa_pem(
        std::env::var("RSA_PRIVATE_KEY")
            .expect("Missing env `RSA_PRIVATE_KEY`")
            .as_bytes(),
    )
    .expect("Failed to load private key");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH!");

    encode(
        &Header::new(Algorithm::RS256),
        &Claims {
            sub: user_id.to_lowercase(),
            scope,
            exp: now.as_secs() + 604800,
            iss: "https://oauth.gravitalia.com".to_string(),
            iat: now.as_secs(),
        },
        &private_key,
    )
    .unwrap()
}

/// Decode a JWT token and check if it is valid
pub fn get_jwt(token: String) -> Result<TokenData<Claims>> {
    let public_key = DecodingKey::from_rsa_pem(
        std::env::var("RSA_PUBLIC_KEY")
            .expect("Missing env `RSA_PUBLIC_KEY`")
            .as_bytes(),
    )
    .expect("Failed to load public key");

    Ok(decode::<Claims>(
        &token,
        &public_key,
        &Validation::new(Algorithm::RS256),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwt() {
        //assert!(regex::Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)").unwrap().is_match(&create_jwt("test".to_string(), vec![])));
    }
}
