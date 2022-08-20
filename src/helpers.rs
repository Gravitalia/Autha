use argon2::{self, Config, ThreadMode, Variant, Version};
use regex::Regex;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};

pub fn random_string() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".chars().collect();
    let mut result = String::new();

    unsafe {
        for _ in 0..9 {
            result.push(
                *chars.get_unchecked(fastrand::usize(0..62))
            );
        }
    }

    result
}

pub fn hash(data: &[u8]) -> String {
    argon2::hash_encoded(
        data,
        random_string().as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 32768,
            time_cost: 7,
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: dotenv::var("KEY").expect("Missing env `KEY`").as_bytes(),
            ad: &[],
            hash_length: 64
        }
    ).unwrap()
}

pub fn encrypt(data: String) -> String {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);

    match hex::decode(dotenv::var("KEY").expect("Missing env `KEY`")) {
        Ok(d) => println!("{:?}", d),
        Err(_) => println!("ok"),
    }

    println!("{}", hex::encode(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    match ChaCha20Poly1305::new(&key).encrypt(&nonce, data.as_bytes().as_ref()) {
        Ok(v) => println!("{}//{}", hex::encode(nonce), hex::encode(v)),
        Err(e) => println!("error parsing header: {e:?}"),
    }

    "test".to_string()
}

#[test]
fn test_hash() {
    assert!(Regex::new(r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*").unwrap().is_match(&hash("password".as_bytes())));
}