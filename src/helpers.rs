use chrono::prelude::*;
use argon2::{self, Config, ThreadMode, Variant, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305
};
use generic_array::GenericArray;
use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, Validation, DecodingKey, TokenData};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::OnceCell;
static ARGON_SECRET: OnceCell<String> = OnceCell::new();
static ROUND: OnceCell<u32> = OnceCell::new();
static HASH_LENGTH: OnceCell<u32> = OnceCell::new();
static CHA_KEY: OnceCell<String> = OnceCell::new();
static RSA_PRIVATE_KEY: OnceCell<String> = OnceCell::new();
static RSA_PUBLIC_KEY: OnceCell<String> = OnceCell::new();

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub nonce: Option<String>,
    aud: Option<String>,
    exp: u128,
    iss: String,
    iat: u128
}

/// Set every variables
#[allow(unused_must_use)]
pub fn init() {
    ARGON_SECRET.set(dotenv::var("KEY").expect("Missing env `KEY`"));
    ROUND.set(dotenv::var("ROUND").expect("Missing env `ROUND`").parse::<u32>().unwrap());
    HASH_LENGTH.set(dotenv::var("HASH_LENGTH").expect("Missing env `HASH_LENGTH`").parse::<u32>().unwrap());
    CHA_KEY.set(dotenv::var("CHA_KEY").expect("Missing env `CHA_KEY`"));
    RSA_PRIVATE_KEY.set(dotenv::var("RSA_PRIVATE_KEY").expect("Missing env `RSA_PRIVATE_KEY`"));
    RSA_PUBLIC_KEY.set(dotenv::var("RSA_PUBLIC_KEY").expect("Missing env `RSA_PUBLIC_KEY`"));
}

/// Generate a random string
/// ```rust
/// let rand = random_string();
/// assert_eq!(random_string().len(), 16);
/// ```
pub fn random_string() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".chars().collect();
    let mut result = String::default();

    unsafe {
        for _ in 0..16 {
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
        random_string().as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 1048576,
            time_cost: *ROUND.get().unwrap(),
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: ARGON_SECRET.get().unwrap().as_bytes(),
            ad: &[],
            hash_length: *HASH_LENGTH.get().unwrap()
        }
    ).unwrap()
}

/// Test if the password is corresponding with another one hashed
pub fn hash_test(hash: &str, pwd: &[u8]) -> bool {
    argon2::verify_encoded_ext(hash, pwd, ARGON_SECRET.get().unwrap().as_bytes(), &[]).unwrap()
}


/// Encrypt data as bytes into String with ChaCha20 (Salsa20) and Poly1305 
#[allow(clippy::type_complexity)]
pub fn encrypt(data: &[u8]) -> String {
    match hex::decode(CHA_KEY.get().unwrap()) {
        Ok(v) => {
            let bytes: generic_array::GenericArray<u8, generic_array::typenum::UInt<generic_array::typenum::UInt<generic_array::typenum::UInt<generic_array::typenum::UInt<generic_array::typenum::UInt<generic_array::typenum::UInt<generic_array::typenum::UTerm, generic_array::typenum::B1>, generic_array::typenum::B0>, generic_array::typenum::B0>, generic_array::typenum::B0>, generic_array::typenum::B0>, generic_array::typenum::B0>> = GenericArray::clone_from_slice(&v);

            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            match ChaCha20Poly1305::new(&bytes).encrypt(&nonce, data) {
                Ok(v) => format!("{}//{}", hex::encode(nonce), hex::encode(v)),
                Err(_) => "Error".to_string(),
            }
        },
        Err(_) => "Error".to_string(),
    }
}

/// Create a JWT token, used for authentification
pub fn create_jwt(user_id: String, finger: Option<String>, nonce: Option<String>) -> String {
    match EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.get().unwrap().as_bytes()) {
        Ok(d) => {
            encode(&Header::new(Algorithm::RS256), &Claims {
                sub: user_id.to_lowercase(),
                aud: finger.map(|val| val[0..24].to_string()),
                exp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()+5259600000,
                iss: "https://oauth.gravitalia.studio".to_string(),
                iat: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                nonce
            }, &d).unwrap()
        },
        Err(_) => "Error".to_string(),
    }
}

// Decode a JWT token and check if it is valid
pub fn get_jwt(token: String) -> Result<TokenData<Claims>, String> {
    match DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY.get().unwrap().as_bytes()) {
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

/// Get age with given data
/// ```rust
/// assert_eq!(get_age(2000, 01, 29), 23);
/// ```
pub fn get_age(year: i32, month: u32, day: u32) -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(date) => {
            (((date.as_millis()
            - NaiveDate::from_ymd_opt(year, month, day).unwrap().and_hms_milli_opt(0, 0, 0, 0).unwrap().and_local_timezone(Utc).unwrap().timestamp_millis() as u128)
            / 31540000000) as f64).floor()
        },
        Err(_) => 0.0
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        init();
        let pwd = &hash(b"password");
        assert!(regex::Regex::new(r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*").unwrap().is_match(pwd));
        assert!(hash_test(pwd, b"password"));
    }
    
    #[test]
    fn test_encrypt() {
        init();
        assert!(regex::Regex::new(r"[0-9a-fA-F]{24}[/]{2}[0-9a-fA-F]+").unwrap().is_match(&encrypt("I'm feeling lucky".as_bytes())));
    }
    
    #[tokio::test]
    async fn test_jwt() {
        init();
        assert!(regex::Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)").unwrap().is_match(&create_jwt("test".to_string(), None, None)));
    }

    #[tokio::test]
    async fn test_random_string() {
        assert_eq!(random_string().len(), 16);
    }
}
