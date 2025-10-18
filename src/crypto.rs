//! Cryptogragic logics.
use aes::Aes256;
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params, Version};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use validator::{ValidationError, ValidationErrors};

use crate::ServerError;

const MAX_NO_OVERHEAD_BLOCK_SIZE: usize = 10_000; // 10,000 bytes.

type Result<T> = std::result::Result<T, Error>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
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
}

/// Action [`Cipher`] should make.
pub enum Action {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Default)]
pub struct Cipher {
    key: Vec<u8>,
}

impl Cipher {
    /// Create a new [`Cipher`] structure with a `key`.
    /// If key have more than 32 bytes, turncate it.
    pub fn key<T: ToString>(key: T) -> Result<Self> {
        Ok(Self {
            key: hex::decode(key.to_string())?,
        })
    }

    fn iv(&self) -> [u8; 16] {
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        iv
    }

    /// Either encrypt or decrypt data with AES256.
    ///
    /// **WARNING**: no iv means less secure.
    pub async fn aes_no_iv(&self, action: Action, data: Vec<u8>) -> Result<String> {
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
            }
            Action::Decrypt => {
                let data = hex::decode(data)?;

                let bytes = tokio::task::spawn_blocking(move || {
                    Aes256::new(&key).decrypt_padded_vec_mut::<Pkcs7>(&data)
                })
                .await
                .map_err(|_| Error::Thread)?;

                Ok(String::from_utf8(bytes?)?)
            }
        }
    }

    /// Either encrypt or decrypt data with AES256-CBC.
    pub async fn aes(&self, action: Action, data: Vec<u8>) -> Result<String> {
        // The key is 32 bytes long. The operation is therefore easy to clone.
        let key = *GenericArray::from_slice(&self.key);
        let iv = self.iv();

        match action {
            Action::Encrypt => {
                let mut message = iv.to_vec();

                // If text is light, avoid thread overhead.
                let cipher_text = if data.len() > MAX_NO_OVERHEAD_BLOCK_SIZE {
                    tokio::task::spawn_blocking(move || {
                        Aes256CbcEnc::new(&key, &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&data)
                    })
                    .await
                    .map_err(|_| Error::Thread)?
                } else {
                    Aes256CbcEnc::new(&key, &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&data)
                };

                message.extend(cipher_text);

                Ok(hex::encode(message))
            }
            Action::Decrypt => {
                let data = hex::decode(data)?;
                let (iv, cipher_text) = data.split_at(16);
                let iv: [u8; 16] = iv.try_into()?;
                let cipher_text = cipher_text.to_vec();

                // If text is light, avoid thread overhead.
                let bytes = if cipher_text.len() > MAX_NO_OVERHEAD_BLOCK_SIZE {
                    tokio::task::spawn_blocking(move || {
                        Aes256CbcDec::new(&key, &iv.into())
                            .decrypt_padded_vec_mut::<Pkcs7>(&cipher_text)
                    })
                    .await
                    .map_err(|_| Error::Thread)??
                } else {
                    Aes256CbcDec::new(&key, &iv.into())
                        .decrypt_padded_vec_mut::<Pkcs7>(&cipher_text)?
                };

                Ok(String::from_utf8(bytes)?)
            }
        }
    }

    /// Hash password using [`argon2`].
    pub async fn hash_password<T: ToString>(&self, password: T) -> crate::error::Result<String> {
        let password = password.to_string();
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(Params::DEFAULT_M_COST * 4, 6, Params::DEFAULT_P_COST, None)
            .map_err(|_| ServerError::Internal {
                details: String::default(),
                source: None,
            })?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let hash = tokio::task::spawn_blocking(move || {
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|_| ServerError::Internal {
                    details: String::default(),
                    source: None,
                })?
                .to_string();
            let hash = PasswordHash::new(&password_hash).map_err(|_| ServerError::Internal {
                details: String::default(),
                source: None,
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
                let error =
                    ValidationError::new("decode").with_message("Invalid password format.".into());
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
        if key.len() > 200 {
            RsaPublicKey::from_public_key_pem(key).map_err(KeyError::Pkcs8)?;
        } else {
            VerifyingKey::from_public_key_pem(key).map_err(KeyError::Pkcs8)?;
        }
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
