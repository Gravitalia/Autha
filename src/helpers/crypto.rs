use anyhow::Result;
use argon2::{Config, Variant, Version};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use ring::digest::{Context, SHA256};
use ring::aead::*;
use std::num::Wrapping;

/// A generator for producing nonces.
struct NonceGen {
    /// The current nonce value, wrapped to handle overflow.
    current: Wrapping<u128>,
    /// The initial value of the nonce generator.
    start: u128,
}

impl NonceGen {
    /// Creates a new NonceGen instance with the provided 12-byte start value.
    fn new(start: [u8; 12]) -> Self {
        let mut array = [0; 16];
        array[..12].copy_from_slice(&start);
        let start = u128::from_le_bytes(array);
        Self {
            current: Wrapping(start),
            start,
        }
    }
}

impl NonceSequence for NonceGen {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        // ! Warning: doesn't check u128 overflow correctly
        // Also, ring docs explicitly call this
        // out as "reasonable (but probably not ideal)"
        let n = self.current.0;
        self.current += 1;
        if self.current.0 == self.start {
            return Err(ring::error::Unspecified);
        }
        Ok(Nonce::assume_unique_for_key(
            n.to_le_bytes()[..12].try_into().unwrap(),
        ))
    }
}

/// Generate random string with thread-local cryptographically-secure PRNG seeded from the system's entropy pool.
pub fn random_string(length: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&"
        .chars()
        .collect();
    let mut result = String::with_capacity(length);
    let mut rng = OsRng;

    for _ in 0..length {
        result.push(chars[rng.gen_range(0..62)]);
    }

    result
}

/// Hash plaintext using Argon2, mostly used for passwords.
/// It uses the two version, Argon2d for GPU attacks and Argon2i for auxiliary channel attacks.
pub fn hash(data: &[u8], vanity: &[u8]) -> String {
    argon2::hash_encoded(
        data,
        random_string(16).as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: std::env::var("MEMORY_COST")
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or(262144),
            time_cost: std::env::var("ROUND")
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or(1),
            lanes: 8,
            secret: std::env::var("KEY")
                .unwrap_or_else(|_| "KEY".to_string())
                .as_bytes(),
            ad: vanity,
            hash_length: std::env::var("HASH_LENGTH")
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or(16),
        },
    )
    .unwrap()
}

/// Verify if provided hash is matching with the plaintext password.
/// Using Argon2 to provide checking.
pub fn check_hash(hash: String, password: &[u8], vanity: &[u8]) -> Result<bool> {
    Ok(argon2::verify_encoded_ext(
        &hash,
        password,
        std::env::var("KEY")
            .unwrap_or_else(|_| "KEY".to_string())
            .as_bytes(),
        vanity,
    )?)
}

/// Compute the SHA256 digest for the bytes data.
pub fn sha256_digest(data: &[u8]) -> Result<String> {
    let mut context = Context::new(&SHA256);

    context.update(data);

    Ok(hex::encode(context.finish()))
}

/// Encrypts the provided data using the CHACHA20_POLY1305 algorithm.
/// Returns a tuple containing the nonce as a hexadecimal string and the encrypted data as a hexadecimal string.
pub fn chacha20_poly1305_encrypt(mut data: Vec<u8>) -> Result<(String, String)> {
    // Get CHACHA20 key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("CHACHA20_KEY").unwrap_or_default();
    let key_bytes: &[u8] = if key.is_empty() {
        &[0; 32]
    } else {
        key.as_bytes()
    };

    // Generate crypto-secure 12 random bytes.
    let mut os_rng = OsRng;
    let mut nonce_seed = [0u8; 12];
    os_rng.fill_bytes(&mut nonce_seed);

    let mut sealing_key = {
        let key = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
        let nonce_gen = NonceGen::new(nonce_seed);
        SealingKey::new(key, nonce_gen)
    };

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .unwrap();

    Ok((hex::encode(nonce_seed), hex::encode(data)))
}

/// Decrypts the provided data using the CHACHA20_POLY1305 algorithm.
/// Returns the decrypted data as a string, or default string if decryption fails.
pub fn chacha20_poly1305_decrypt(
    nonce: [u8; 12],
    mut data: Vec<u8>,
) -> Result<String, std::string::FromUtf8Error> {
    // Get CHACHA20 key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("CHACHA20_KEY").unwrap_or_default();
    let key_bytes: &[u8] = if key.is_empty() {
        &[0; 32]
    } else {
        key.as_bytes()
    };

    let mut opening_key = {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes).unwrap();
        let nonce_gen = NonceGen::new(nonce);
        OpeningKey::new(key, nonce_gen)
    };

    match opening_key.open_in_place(Aad::empty(), &mut data) {
        Ok(res) => String::from_utf8(res.to_vec()),
        Err(_) => {
            log::error!(
                "Cannot decrypt ChaCha20-Poly1205 data, got an error during opening. Have you decoded hex before call the function?"
            );

            Ok("".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_random_string() {
        let str = random_string(16);
        assert_eq!(str.len(), 16);
        assert_eq!(
            regex::Regex::new(
                r"[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&]*"
            )
            .unwrap()
            .find_iter(&str)
            .count(),
            1
        );
    }

    #[tokio::test]
    async fn test_hash() {
        let pwd = hash(b"password", b"test");
        assert!(regex::Regex::new(
            r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*"
        )
        .unwrap()
        .is_match(&pwd));
        assert!(check_hash(pwd, b"password", b"test").unwrap_or(false));
    }

    #[tokio::test]
    async fn test_sha256_digest() {
        let hash = sha256_digest(b"rainbow");

        assert_eq!(
            hash.unwrap(),
            "8fced00b6ce281456d69daef5f2b33eaf1a4a29b5923ebe5f1f2c54f5886c7a3".to_string()
        );
    }

    #[tokio::test]
    async fn test_chacha20_poly1305() {
        let plaintext = "2018-07-22";

        // Encrypt and get nonce and encrypted text.
        let (hex_nonce, encrypted) =
            chacha20_poly1305_encrypt(plaintext.as_bytes().to_vec()).unwrap_or_default();

        // Convert nonce as hex to nonce in 12-bytes.
        let nonce: [u8; 12] = hex::decode(hex_nonce)
            .unwrap_or_default()
            .try_into()
            .unwrap_or_default();
        let decrypted =
            chacha20_poly1305_decrypt(nonce, hex::decode(encrypted).unwrap_or_default())
                .unwrap_or_default();

        assert_eq!(decrypted, plaintext.to_string())
    }
}
