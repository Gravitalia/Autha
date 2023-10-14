use anyhow::Result;
use argon2::{Config, Variant, Version};
use rand::rngs::OsRng;
use rand::Rng;

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
}
