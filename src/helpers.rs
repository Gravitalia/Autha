use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit, OsRng}, ChaCha20Poly1305};
use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use argon2::{self, Config, ThreadMode, Variant, Version};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use generic_array::GenericArray;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    exp: u128,
    iss: String,
    iat: u128
}

/// Generate a random string
/// ```rust
/// let rand = random_string(23);
/// assert_eq!(random_string(16).len(), 16);
/// ```
pub fn random_string(length: i32) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".chars().collect();
    let mut result = String::default();

    unsafe {
        for _ in 0..length {
            result.push(
                *chars.get_unchecked(fastrand::usize(0..62))
            );
        }
    }

    result
}

/// Hash data in bytes using Argon2id
pub fn hash(data: &[u8]) -> String {
    argon2::hash_encoded(
        data,
        random_string(16).as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 524288,
            time_cost: 1,
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: dotenv::var("KEY").expect("Missing env `KEY`").as_bytes(),
            ad: &[],
            hash_length: 32
        }
    ).unwrap()
}

/// Test if the password is corresponding with another one hashed
pub fn hash_test(hash: &str, pwd: &[u8]) -> bool {
    argon2::verify_encoded_ext(hash, pwd, dotenv::var("KEY").expect("Missing env `KEY`").as_bytes(), &[]).unwrap_or(false)
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

/// Encrypt data as bytes into String with ChaCha20 (Salsa20) and Poly1305 
#[allow(clippy::type_complexity)]
pub fn encrypt(data: &[u8]) -> String {
    match hex::decode(dotenv::var("CHA_KEY").expect("Missing env `CHA_KEY`")) {
        Ok(v) => {
            let bytes = GenericArray::clone_from_slice(&v);

            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            match ChaCha20Poly1305::new(&bytes).encrypt(&nonce, data) {
                Ok(v) => format!("{}//{}", hex::encode(nonce), hex::encode(v)),
                Err(_) => "Error".to_string(),
            }
        },
        Err(_) => "Error".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let pwd = &hash(b"password");
        assert!(regex::Regex::new(r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*").unwrap().is_match(pwd));
        assert!(hash_test(pwd, b"password"));
    }

    #[tokio::test]
    async fn test_random_string() {
        assert_eq!(random_string(16).len(), 16);
    }

    #[tokio::test]
    async fn test_jwt() {
        assert!(regex::Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)").unwrap().is_match(&create_jwt("test".to_string())));
    }
}