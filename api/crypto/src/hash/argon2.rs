#[cfg(feature = "argon2")]
use argon2::{Config, Error, Variant, Version};

/// Configuration for Argon2id.
#[derive(Debug, Default, Clone)]
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
///
/// # Examples
///
/// ```rust
/// use crypto::hash::argon2::{argon2, Argon2Configuration};
///
/// let config = Argon2Configuration {
///     memory_cost: 262144,
///     round: 1,
///     lanes: 8,
///     secret: "KEY".to_string(),
///     hash_length: 16,
/// };
///
/// println!("SuperPassword is {}", argon2(config, b"SuperPassword", None).unwrap());
/// ```
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
///
/// # Examples
///
///```rust
/// use crypto::hash::argon2::{argon2, Argon2Configuration, check_argon2};
///
/// let plaintext = b"Password1234";
/// 
/// let secret = "KEY".to_string();
/// let config = Argon2Configuration {
///     memory_cost: 262144,
///     round: 1,
///     lanes: 8,
///     secret: secret.clone(),
///     hash_length: 16,
/// };
/// let hashed_password = argon2(config, plaintext, None).unwrap();
///
/// println!("Is that working? {:?}", check_argon2(secret.as_bytes(), hashed_password, plaintext, None));
/// ```
#[cfg(feature = "argon2")]
pub fn check_argon2(
    secret: &[u8],
    hash: String,
    password: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<bool, Error> {
    argon2::verify_encoded_ext(
        &hash,
        password,
        secret,
        associated_data.unwrap_or(&[]),
    )
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
            secret: "SECRET_KEY".to_string(),
            hash_length: 16,
        };

        let pwd = argon2(config, b"password", Some(b"test")).unwrap();

        assert!(Regex::new(
            r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*"
        )
        .unwrap()
        .is_match(&pwd));
        assert!(check_argon2(b"SECRET_KEY", pwd, b"password", Some(b"test"))
            .unwrap_or(false));
    }
}
