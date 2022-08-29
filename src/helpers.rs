use argon2::{self, Config, ThreadMode, Variant, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305
};
use generic_array::GenericArray;
use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: Option<String>,
    exp: u128,
    iss: String,
    iat: u128
}

pub fn random_string() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".chars().collect();
    let mut result = String::new();

    unsafe {
        for _ in 0..16 {
            result.push(
                *chars.get_unchecked(fastrand::usize(0..62))
            );
        }
    }

    result
}

pub fn hash(data: &[u8]) -> String {
    println!("{}", dotenv::var("KEY").expect("Missing env `KEY`"));
    argon2::hash_encoded(
        data,
        random_string().as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 1048576,
            time_cost: dotenv::var("ROUND").expect("Missing env `ROUND`").parse::<u32>().unwrap(),
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: dotenv::var("KEY").expect("Missing env `KEY`").as_bytes(),
            ad: &[],
            hash_length: dotenv::var("HASH_LENGTH").expect("Missing env `HASH_LENGTH`").parse::<u32>().unwrap()
        }
    ).unwrap()
}

pub fn encrypt(data: &[u8]) -> String {
    match hex::decode(dotenv::var("CHA_KEY").expect("Missing env `CHA_KEY`")) {
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

pub fn create_jwt(user_id: String, finger: Option<String>) -> String {
    match EncodingKey::from_rsa_pem(dotenv::var("RSA_PRIVATE_KEY").expect("Missing env `RSA_PRIVATE_KEY`").as_bytes()) {
        Ok(d) => {
            encode(&Header::new(Algorithm::RS256), &Claims {
                sub: user_id,
                aud: finger,
                exp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()+5259600000,
                iss: "https://oauth.gravitalia.studio".to_string(),
                iat: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
            }, &d).unwrap()
        },
        Err(_) => "Error".to_string(),
    }
}

#[test]
fn test_hash() {
    assert!(regex::Regex::new(r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*").unwrap().is_match(&hash("password".as_bytes())));
}

#[test]
fn test_encrypt() {
    assert!(regex::Regex::new(r"[0-9a-fA-F]{24}[/]{2}[0-9a-fA-F]+").unwrap().is_match(&encrypt("I'm feeling lucky".as_bytes())));
}

#[test]
fn test_jwt() {
    assert!(regex::Regex::new(r"(^[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$)").unwrap().is_match(&create_jwt("test".to_string(), None)));
}