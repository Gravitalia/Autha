//! Cryptogragic logics.

use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray;
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
use sha2::{Digest, Sha256};
use validator::{ValidationError, ValidationErrors};
use zeroize::Zeroizing;

use crate::ServerError;
use crate::config::Argon2 as ArgonConfig;

const _MAX_NO_OVERHEAD_BLOCK_SIZE: usize = 10_000; // 10,000 bytes.
const NONCE_SIZE: usize = 12;
const KEY_LENGTH: usize = 32;

type Result<T> = std::result::Result<T, CryptoError>;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error(transparent)]
    AesGcm(#[from] aes_gcm::Error),
    #[error("argon2 error: {0}")]
    Argon2(String),

    #[error("hex is not valid")]
    Hex(#[from] hex::FromHexError),
    #[error("failed to slice iv")]
    Slice(#[from] std::array::TryFromSliceError),
    #[error("encrypted data is not utf8")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("key length is {value} while {excepted} is excepted")]
    KeyLength { value: usize, excepted: usize },
}

/// Cryptographic manager.
pub struct Crypto {
    pub symmetric: SymmetricCipher,
    pub pwd: PasswordManager,
    pub hasher: Hasher,
}

impl Crypto {
    /// Create a new [`Crypto`].
    pub fn new(
        config: Option<ArgonConfig>,
        master_key: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let key = SymmetricKey::derive_from_password(master_key, &salt)?;
        let symmetric = SymmetricCipher::new(key);
        let pwd = PasswordManager::new(config)?;
        let hasher = Hasher::new(salt);

        Ok(Self {
            symmetric,
            pwd,
            hasher,
        })
    }
}

/// SymmetricKey holds a fixed-size key protected by Zeroizing.
#[derive(Clone)]
pub struct SymmetricKey(Zeroizing<[u8; KEY_LENGTH]>);

impl SymmetricKey {
    /// Create from raw bytes (must be 32 bytes).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes.try_into().unwrap()))
    }

    /// Derive key from a password + salt using Argon2.
    pub fn derive_from_password(
        password: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let config = ArgonConfig {
            memory_cost: 1024 * 64,
            iterations: 8,
            parallelism: 2,
            hash_length: KEY_LENGTH,
            ..Default::default()
        };

        let mut pwd = PasswordManager::new(Some(config))?;
        pwd.salt(Some(salt.as_ref().to_vec()));
        let phc_hash_string = pwd.hash_password(password)?;
        pwd.salt(None); // remove fixed salt.
        let password_hash = PasswordHash::new(&phc_hash_string)
            .map_err(|e| CryptoError::Argon2(e.to_string()))?;

        Ok(Self::from_bytes(
            password_hash.hash.unwrap().as_bytes().to_vec(),
        ))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// SymmetricCipher provides encrypt/decrypt operations with AES-256-GCM.
pub struct SymmetricCipher {
    key: SymmetricKey,
}

impl SymmetricCipher {
    /// Create a new [`SymmetricCipher`].
    pub fn new(key: SymmetricKey) -> Self {
        Self { key }
    }

    pub fn encrypt_and_hex(
        &self,
        plaintext: impl AsRef<[u8]>,
    ) -> Result<String> {
        let cipher_text = self.encrypt(plaintext)?;
        Ok(hex::encode(cipher_text))
    }

    pub fn decrypt_from_hex(&self, data: impl AsRef<[u8]>) -> Result<String> {
        let data = hex::decode(data)?;
        let plain = self.decrypt(data)?;
        Ok(String::from_utf8(plain)?)
    }

    /// Encrypts data returning raw bytes.
    pub fn encrypt(&self, plaintext: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(self.key.as_slice());
        let cipher = Aes256Gcm::new(key);

        // Generate random 96-bit nonce.
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let cipher_text = cipher.encrypt(nonce, plaintext.as_ref())?;

        let mut out = Vec::with_capacity(NONCE_SIZE + cipher_text.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&cipher_text);
        Ok(out)
    }

    /// Decrypt raw data.
    pub fn decrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let data = data.as_ref();
        if data.len() < NONCE_SIZE {
            return Err(CryptoError::KeyLength {
                value: data.len(),
                excepted: NONCE_SIZE,
            });
        }

        let (nonce_bytes, cipher_text) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::<Aes256Gcm>::clone_from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(self.key.as_slice());
        let cipher = Aes256Gcm::new(key);

        let plain = cipher.decrypt(&nonce, cipher_text.as_ref())?;

        Ok(plain)
    }

    /// Check TOTP code.
    pub fn check_totp(
        &self,
        code: Option<&str>,
        secret: Option<&str>,
    ) -> crate::error::Result<()> {
        if let Some(secret) = secret {
            let secret = self.decrypt_from_hex(secret)?;
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

/// Password manager that uses Argon2id and PHC string format for hashing and
/// verification.
pub struct PasswordManager {
    params: Params,
    fixed_salt: Option<Vec<u8>>,
}

impl PasswordManager {
    /// Create a new [`PasswordManager`].
    pub fn new(config: Option<ArgonConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();

        let params = Params::new(
            config.memory_cost,
            config.iterations,
            config.parallelism,
            Some(config.hash_length),
        )
        .map_err(|err| CryptoError::Argon2(err.to_string()))?;

        Ok(Self {
            params,
            fixed_salt: None,
        })
    }

    /// Set a fixed salt.
    /// **Used for derivation password only!**
    fn salt(&mut self, salt: Option<Vec<u8>>) {
        self.fixed_salt = salt;
    }

    /// Hash password using Argon2id.
    pub fn hash_password(
        &self,
        password: impl AsRef<[u8]>,
    ) -> std::result::Result<String, CryptoError> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            self.params.clone(),
        );
        let salt = match &self.fixed_salt {
            Some(salt) => SaltString::encode_b64(salt)
                .map_err(|e| CryptoError::Argon2(e.to_string()))?,
            None => SaltString::generate(&mut OsRng),
        };
        let hash = argon2
            .hash_password(password.as_ref(), &salt)
            .map_err(|e| CryptoError::Argon2(e.to_string()))?;

        Ok(hash.to_string())
    }

    fn invalid_password() -> ValidationErrors {
        let mut errors = ValidationErrors::new();
        errors.add(
            "password",
            ValidationError::new("invalid_password")
                .with_message("Invalid password.".into()),
        );
        errors
    }

    /// Verify password against a PHC.
    pub fn verify_password(
        &self,
        password: impl AsRef<[u8]>,
        phc_hash: impl ToString,
    ) -> std::result::Result<(), ValidationErrors> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            Version::V0x13,
            self.params.clone(),
        );
        let phc_hash = phc_hash.to_string();

        let parsed = PasswordHash::new(&phc_hash)
            .map_err(|_| Self::invalid_password())?;

        argon2
            .verify_password(password.as_ref(), &parsed)
            .map_err(|_| Self::invalid_password())
    }
}

pub struct Hasher(Zeroizing<Vec<u8>>);

impl Hasher {
    /// Create a new [`Hash`].
    pub fn new(pepper: impl AsRef<[u8]>) -> Self {
        Self(Zeroizing::new(pepper.as_ref().to_vec()))
    }

    /// Digest data into SHA256.
    pub fn digest(&self, data: impl AsRef<[u8]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.0);
        hasher.update(&data);
        let hash = hasher.finalize();

        hex::encode(hash)
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

    #[test]
    fn test_sha2() {
        let salt = [0x42; 16];
        let hasher = Hasher::new(salt);

        let plaintext = b"super_secret_data";
        let excepted =
            "ec0797340f6163ddc7398d7eafba6e05a8cb041a3935bbdaef99088917cc8933";

        let hash = hasher.digest(plaintext);
        assert_eq!(hash, excepted)
    }

    #[test]
    fn test_aes256() {
        let salt = [0x42; 16];
        let pwd = "secret";
        let key = SymmetricKey::derive_from_password(pwd, salt).unwrap();
        let cipher = SymmetricCipher::new(key);

        let plaintext = "super_secret_data";
        let encrypted_data = cipher.encrypt(plaintext).unwrap();
        let decrypted_data = cipher.decrypt(encrypted_data).unwrap();

        assert_eq!(plaintext.as_bytes(), decrypted_data);
    }
}
