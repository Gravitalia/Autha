//! Cryptogragic logics.

use aes::Aes256;
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes256Gcm, Key};
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Argon2, Params, Version};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use validator::{ValidationError, ValidationErrors};
use zeroize::Zeroizing;

use crate::ServerError;

const MAX_NO_OVERHEAD_BLOCK_SIZE: usize = 10_000; // 10,000 bytes.
const NONCE_SIZE: usize = 12;

type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    AesGcm(#[from] aes_gcm::Error),
    #[error("hex is not valid")]
    Hex(#[from] hex::FromHexError),
    #[error("failed to slice iv")]
    Slice(#[from] std::array::TryFromSliceError),
    #[error("unpadding decryption error, {0}")]
    Unpad(#[from] UnpadError),
    #[error("was encrypted data string?")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("tokio blocking thread crashed")]
    Thread,
    #[error("key length is {value} while {excepted} is excepted")]
    KeyLength { value: usize, excepted: usize },
}

/// Action [`Cipher`] should make.
pub enum Action {
    Encrypt,
    Decrypt,
}

/// Cryptographic manager.
#[derive(Clone)]
pub struct Cipher {
    key: Zeroizing<Vec<u8>>,
    pub memory_cost: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub hash_length: usize,
}

impl Default for Cipher {
    fn default() -> Self {
        Self {
            key: Zeroizing::new(Vec::new()),
            memory_cost: 1024 * 64, // 64 MiB.
            iterations: 4,
            parallelism: 2,
            hash_length: 32,
        }
    }
}

impl Cipher {
    /// Create a new [`Cipher`] structure with a `key`.
    pub fn key<T: ToString>(key: T) -> Result<Self> {
        let mut cipher = Self::default();

        const KEY_LENGTH: usize = 32;
        let mut key = Zeroizing::new(hex::decode(key.to_string())?);
        key.truncate(KEY_LENGTH);

        if key.len() < KEY_LENGTH {
            return Err(Error::KeyLength {
                value: key.len(),
                excepted: KEY_LENGTH,
            });
        }

        cipher.key = key;
        Ok(cipher)
    }

    fn iv() -> [u8; NONCE_SIZE] {
        let mut iv = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut iv);
        iv
    }

    /// Either encrypt or decrypt data with AES256.
    ///
    /// # Security issues
    /// * **Deterministic**: function does not use IV and is therefore deterministic.
    /// * **ECB mode**: patterns remain identifiable
    ///
    /// Please **never use this function** except where weak security is better than nothing.
    pub async fn aes_no_iv(
        &self,
        action: Action,
        data: Vec<u8>,
    ) -> Result<String> {
        // The key is 32 bytes long. The operation is therefore easy to clone.
        let key = *GenericArray::from_slice(&self.key);

        match action {
            Action::Encrypt => {
                let message = tokio::task::spawn_blocking(move || {
                    Aes256::new(&key).encrypt_padded_vec::<Pkcs7>(&data)
                })
                .await
                .map_err(|_| Error::Thread)?;
                Ok(hex::encode(message))
            },
            Action::Decrypt => {
                let data = hex::decode(data)?;

                let bytes = tokio::task::spawn_blocking(move || {
                    Aes256::new(&key).decrypt_padded_vec_mut::<Pkcs7>(&data)
                })
                .await
                .map_err(|_| Error::Thread)?;

                Ok(String::from_utf8(bytes?)?)
            },
        }
    }

    /// Either encrypt or decrypt data with AES256-GCM.
    pub async fn aes(&self, action: Action, data: Vec<u8>) -> Result<String> {
        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        match action {
            Action::Encrypt => {
                let nonce = Self::iv();
                let nonce = GenericArray::clone_from_slice(&nonce);

                let cipher_text = if data.len() > MAX_NO_OVERHEAD_BLOCK_SIZE {
                    tokio::task::spawn_blocking(move || {
                        cipher.encrypt(&nonce, data.as_ref())
                    })
                    .await
                    .map_err(|_| Error::Thread)??
                } else {
                    cipher.encrypt(&nonce, data.as_ref())?
                };

                let mut message = nonce.to_vec();
                message.extend(cipher_text);

                Ok(hex::encode(message))
            },
            Action::Decrypt => {
                let data = hex::decode(data)?;
                let (nonce, cipher_text) = data.split_at(NONCE_SIZE);

                let nonce = Nonce::<Aes256Gcm>::clone_from_slice(nonce);
                let cipher_text = cipher_text.to_vec();

                let bytes = if cipher_text.len() > MAX_NO_OVERHEAD_BLOCK_SIZE {
                    tokio::task::spawn_blocking(move || {
                        cipher.decrypt(&nonce, cipher_text.as_ref())
                    })
                    .await
                    .map_err(|_| Error::Thread)??
                } else {
                    cipher.decrypt(&nonce, cipher_text.as_ref())?
                };

                Ok(String::from_utf8(bytes)?)
            },
        }
    }

    /// Hash password using [`argon2`].
    pub async fn hash_password<T: ToString>(
        &self,
        password: T,
    ) -> crate::error::Result<String> {
        let password = Zeroizing::new(password.to_string());
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(
            self.memory_cost,
            self.iterations,
            self.parallelism,
            Some(self.hash_length),
        )
        .map_err(|err| ServerError::Internal {
            details: err.to_string(),
            source: None,
        })?;
        let argon2 =
            Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let hash = tokio::task::spawn_blocking(move || {
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|err| ServerError::Internal {
                    details: err.to_string(),
                    source: None,
                })?
                .to_string();
            let hash = PasswordHash::new(&password_hash).map_err(|err| {
                ServerError::Internal {
                    details: err.to_string(),
                    source: None,
                }
            })?;

            Ok::<String, ServerError>(hash.to_string())
        })
        .await
        .map_err(|err| ServerError::Internal {
            details: String::default(),
            source: Some(Box::new(err)),
        })??;

        Ok(hash)
    }

    /// Check plaintext password with Argon2-hashed password.
    pub async fn check_password<T: ToString>(
        &self,
        pwd: T,
        hash: T,
    ) -> std::result::Result<(), ValidationErrors> {
        let plaintext = pwd.to_string();
        let hash = hash.to_string();

        tokio::task::spawn_blocking(move || {
            let hash = PasswordHash::new(&hash).map_err(|err| {
                tracing::error!(%err, "password hash decoding failed");
                let error = ValidationError::new("decode")
                    .with_message("Invalid password format.".into());
                let mut errors = ValidationErrors::new();
                errors.add("password", error);
                errors
            })?;

            Argon2::default()
                .verify_password(plaintext.as_bytes(), &hash)
                .map_err(|_| {
                    let error = ValidationError::new("invalid_password")
                        .with_message("Invalid password format.".into());
                    let mut errors = ValidationErrors::new();
                    errors.add("password", error);
                    errors
                })
        })
        .await
        .map_err(|_| {
            let error = ValidationError::new("invalid_password")
                .with_message("Invalid password format.".into());
            let mut errors = ValidationErrors::new();
            errors.add("password", error);
            errors
        })?
    }

    pub async fn check_totp(
        &self,
        code: Option<String>,
        secret: &Option<String>,
    ) -> crate::error::Result<()> {
        if let Some(secret) = secret {
            let secret = self
                .aes(crate::crypto::Action::Decrypt, secret.as_bytes().to_vec())
                .await
                .map_err(|err| ServerError::Internal {
                    details: "decode totp secret".into(),
                    source: Some(Box::new(err)),
                })?;
            let mut errors = validator::ValidationErrors::new();

            if let Some(code) = code {
                if crate::totp::generate_totp(&secret, 30, 6)? != code {
                    errors.add(
                        "totpCode",
                        validator::ValidationError::new("invalid_totp")
                            .with_message("TOTP code is wrong.".into()),
                    );
                }
            } else {
                errors.add(
                    "totpCode",
                    validator::ValidationError::new("invalid_totp")
                        .with_message("Missing 'totpCode' field.".into()),
                );
            }

            if !errors.is_empty() {
                return Err(ServerError::Validation(errors));
            }
        }

        Ok(())
    }
}

/// Error related to public keys.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(transparent)]
    Pkcs1(#[from] rsa::pkcs1::Error),

    #[error(transparent)]
    Pkcs8(#[from] rsa::pkcs8::spki::Error),

    #[error("unknown public key format")]
    UnknownFormat,
}

/// Check if a key is well-formatted.
pub fn check_key(key: &str) -> std::result::Result<(), KeyError> {
    if key.contains("BEGIN RSA PUBLIC KEY") {
        // Means it is PKCS#1 and only RSA.
        RsaPublicKey::from_pkcs1_pem(key).map_err(KeyError::Pkcs1)?;
    } else if key.contains("BEGIN PUBLIC KEY") {
        // Means it is PKCS#8 and could be even RSA or ECDSA.
        RsaPublicKey::from_public_key_pem(key)
            .map(|_| ())
            .or_else(|_| VerifyingKey::from_public_key_pem(key).map(|_| ()))
            .map_err(KeyError::Pkcs8)?;
    } else {
        return Err(KeyError::UnknownFormat);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aes_no_iv() {
        const EMAIL: &str = "admin@gravitalia.com";

        let key = [0x42; 32];
        let cipher = Cipher::key(hex::encode(key)).unwrap();

        let cipher_text = cipher
            .aes_no_iv(Action::Encrypt, EMAIL.into())
            .await
            .unwrap();

        assert_eq!(
            cipher_text,
            "3601ff3a929d30b044c7ec7722c0d5da0fcba9acca82ded8b781e999b01aa33a"
        );

        assert_eq!(
            cipher
                .aes_no_iv(Action::Decrypt, cipher_text.into())
                .await
                .unwrap(),
            EMAIL,
        );
    }

    #[test]
    fn test_rsa() {
        // There is no env.
        const REAL_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH/cOrXe5GfnKdiFjP4T4g+WyKHE
9WroOd0d6zbfsGuhEAYEmoSXV9HW1/HbLObzRb/O5yBC8Cb/sEyCGhgkSDelpQev
sdhTB1QMqUXLcft1ehq0+4ZGrx0czfg3TYg60FX2nbtJOz4eQHa8kIif8NJsSpDW
x7tMF74uf+o+1cNdAgMBAAE=
-----END PUBLIC KEY-----"#;

        assert!(check_key(REAL_KEY).is_ok());

        const FAKE_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCFhLBHV3S7h7DBTaBqPPg3Vrsy
dvnqaT8jLUzgfOKxpizKYC1dtQx2JETAIMEJULIEN+OtA8/OU_PASDhaLnzkb6crTNojIokSXPWR
7+VbBcsNVMhl3QneN1hpgRwlSAit8LfsRGFuuvj5Zb9cNMKPyFekXA0vPjH2OZMV
GzdTXR1DHFS8P/saJQIDAQAB
-----END PUBLIC KEY-----"#;
        assert!(check_key(FAKE_KEY).is_err());
    }

    #[test]
    fn test_ecdsa() {
        // There is no env.
        const REAL_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElInmvVOpx1FjEDIH6dGC6CxbtBjx
02gUk8op1zxJvuA1zL0Pe07KO6wIjr+Ndi6HteDfqsC4Kzg+xDrUdTwRtw==
-----END PUBLIC KEY-----"#;

        assert!(check_key(REAL_KEY).is_ok());

        const FAKE_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEMcCSmtPOJLBrFImsV59akn3pmwGuebiT
pQkthCHdjBbLyMZDI//d7+I3AxnZ+/QyFO32e8tvkYdAT4MM2jb0AyxA
-----END PUBLIC KEY-----"#;
        assert!(check_key(FAKE_KEY).is_err());
    }
}
