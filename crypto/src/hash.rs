#[cfg(feature = "argon2")]
use argon2::{Config, Error, Variant, Version};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};

/// Configuration for Argon2id.
#[derive(Default, Clone)]
pub struct Argon2Configuration {
    /// Amount of memory used in KB.
    pub memory_cost: u32,
    /// Higher is better, higher is slower.
    pub round: u32,
    /// Task parallelization. Usually half the number of your CPU cores.
    pub lanes: u32,
    /// Private key used for hashing.
    pub secret: String,
    /// Length of final hash. A higher hash may be longer, but more secure.
    pub hash_length: u32,
}

/// Hash plaintext using Argon2, mostly used for passwords.
/// It uses the two version, Argon2d for GPU attacks and Argon2i for auxiliary channel attacks.
#[cfg(feature = "argon2")]
pub fn argon2(
    config: Argon2Configuration,
    data: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<String, Error> {
    argon2::hash_encoded(
        data,
        crate::random_string(16).as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: config.memory_cost,
            time_cost: config.round,
            lanes: config.lanes,
            secret: config.secret.as_bytes(),
            ad: associated_data.unwrap_or(&[]),
            hash_length: config.hash_length,
        },
    )
}

/// Verify if provided hash is matching with the plaintext password.
/// Using Argon2 to provide checking.
#[cfg(feature = "argon2")]
pub fn check_argon2(
    hash: String,
    password: &[u8],
    vanity: &[u8],
) -> Result<bool, Error> {
    argon2::verify_encoded_ext(
        &hash,
        password,
        std::env::var("KEY")
            .unwrap_or_else(|_| "KEY".to_string())
            .as_bytes(),
        vanity,
    )
}

/// Compute the SHA256 digest for the bytes data.
pub fn sha256(data: &[u8]) -> String {
    let mut context = Context::new(&SHA256);

    context.update(data);

    hex::encode(context.finish())
}

/// Compute the SHA1 digest for the bytes data.
///
/// # Warning
/// This should only be used when security is not a priority.
pub fn sha1(data: &[u8]) -> String {
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);

    context.update(data);

    hex::encode(context.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "argon2")]
    use regex_lite::Regex;

    #[test]
    #[cfg(feature = "argon2")]
    fn test_argon2() {
        let config = Argon2Configuration {
            memory_cost: 262144,
            round: 1,
            lanes: 8,
            secret: "KEY".to_string(),
            hash_length: 16,
        };

        let pwd = argon2(config, b"password", Some(b"test")).unwrap();

        assert!(Regex::new(
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
            hash,
            "8fced00b6ce281456d69daef5f2b33eaf1a4a29b5923ebe5f1f2c54f5886c7a3"
                .to_string()
        );
    }

    #[test]
    fn test_sha1() {
        let hash = sha1(b"hello world!");

        assert_eq!(
            hash,
            "430ce34d020724ed75a196dfc2ad67c77772d169".to_string()
        );
    }
}
