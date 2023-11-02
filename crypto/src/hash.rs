use anyhow::Result;
use argon2::{Config, Variant, Version};
use ring::digest::{Context, SHA256};

/// Hash plaintext using Argon2, mostly used for passwords.
/// It uses the two version, Argon2d for GPU attacks and Argon2i for auxiliary channel attacks.
pub fn argon2(data: &[u8], vanity: &[u8]) -> String {
    argon2::hash_encoded(
        data,
        crate::random_string(16).as_bytes(),
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
pub fn check_argon2(hash: String, password: &[u8], vanity: &[u8]) -> Result<bool> {
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
pub fn sha256(data: &[u8]) -> Result<String> {
    let mut context = Context::new(&SHA256);

    context.update(data);

    Ok(hex::encode(context.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2() {
        let pwd = argon2(b"password", b"test");
        assert!(regex::Regex::new(
            r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*"
        )
        .unwrap()
        .is_match(&pwd));
        assert!(check_argon2(pwd, b"password", b"test").unwrap_or(false));
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"rainbow");

        assert_eq!(
            hash.unwrap(),
            "8fced00b6ce281456d69daef5f2b33eaf1a4a29b5923ebe5f1f2c54f5886c7a3".to_string()
        );
    }
}
