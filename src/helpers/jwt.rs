use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, Validation, DecodingKey, TokenData};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    exp: u128,
    iss: String,
    iat: u128
}

/// Create a JWT token
pub fn create_jwt(user_id: String) -> String {
    match EncodingKey::from_rsa_pem(dotenv::var("RSA_PRIVATE_KEY").expect("Missing env `RSA_PRIVATE_KEY`").as_bytes()) {
        Ok(d) => {
            encode(&Header::new(Algorithm::RS256), &Claims {
                sub: user_id.to_lowercase(),
                exp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()+5259600000,
                iss: "https://oauth.gravitalia.com".to_string(),
                iat: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
            }, &d).unwrap()
        },
        Err(_) => "Error".to_string(),
    }
}

/// Decode a JWT token and check if it is valid
pub fn get_jwt(token: String) -> Result<TokenData<Claims>, String> {
    match DecodingKey::from_rsa_pem(dotenv::var("RSA_PUBLIC_KEY").expect("Missing env `RSA_PUBLIC_KEY`").as_bytes()) {
        Ok(d) => {
            match decode::<Claims>(&token, &d, &Validation::new(Algorithm::RS256)) {
                Ok(token_data) => {
                    Ok(token_data)
                },
                Err(err) => Err(err.to_string()),
            }
        },
        Err(_) => Err("Error".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwt() {
        assert!(regex::Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)").unwrap().is_match(&create_jwt("test".to_string())));
    }
}