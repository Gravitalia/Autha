//! AES-256-GCM symmetric encryption implementation.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use application::error::{ApplicationError, Result};
use application::ports::outbound::SymmetricEncryption;
use rand::RngCore;
use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;
const NONCE_SIZE: usize = 12;

/// AES-256-GCM encryption adapter.
pub struct AesGcmEncryption(Zeroizing<[u8; KEY_LENGTH]>);

impl AesGcmEncryption {
    /// Create a new [`AesGcmEncryption`].
    /// Derives a 256-bit key from password and salt using PBKDF2.
    pub fn new(master_key: Zeroizing<Vec<u8>>, salt: &[u8]) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
        Self::derive_key(&master_key, salt, &mut *key)?;
        Ok(Self(Zeroizing::new(*key)))
    }

    fn derive_key(
        password: &[u8],
        salt: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        use argon2::Argon2;

        let params = argon2::Params::default();
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        argon2
            .hash_password_into(password, salt, output)
            .map_err(|err| ApplicationError::Crypto {
                cause: err.to_string(),
            })?;

        Ok(())
    }
}

impl SymmetricEncryption for AesGcmEncryption {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(self.0.as_slice());
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|err| {
            ApplicationError::Crypto {
                cause: err.to_string(),
            }
        })?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(ApplicationError::Crypto {
                cause: "ciphertext too short".to_string(),
            });
        }

        let (nonce_bytes, ciphertext) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(self.0.as_slice());
        let cipher = Aes256Gcm::new(key);

        cipher.decrypt(nonce, ciphertext).map_err(|err| {
            ApplicationError::Crypto {
                cause: err.to_string(),
            }
        })
    }

    fn encrypt_to_hex(&self, plaintext: &[u8]) -> Result<String> {
        let ciphertext = self.encrypt(plaintext)?;
        Ok(hex::encode(ciphertext))
    }

    fn decrypt_from_hex(&self, hex_ciphertext: &str) -> Result<Vec<u8>> {
        let ciphertext = hex::decode(hex_ciphertext)
            .map_err(|_| ApplicationError::Unknown)?;
        self.decrypt(&ciphertext)
    }
}
