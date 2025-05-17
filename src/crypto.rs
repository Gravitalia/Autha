//! Cryptogragic logics.
use aes::cipher::block_padding::{Pkcs7, UnpadError};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;

use crate::ServerError;

const RADIX: u32 = 256;

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
}

/// Action [`Cipher`] should make.
pub enum Action {
    Encrypt,
    Decrypt,
}

#[derive(Clone)]
pub struct Cipher {
    key: Vec<u8>,
}

impl Cipher {
    /// Create a new [`Cipher`] structure with a `key`.
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

    /// Encrypt plaintext with FPE.
    pub fn format_preserving(&self, plaintext: &str) -> String {
        FF1::<Aes256>::new(&self.key, RADIX)
            .ok()
            .and_then(|ff| {
                let email: Vec<u16> = plaintext.encode_utf16().collect();
                let email_length = email.len();

                ff.encrypt(&[], &FlexibleNumeralString::from(email))
                    .ok()
                    .map(|encrypted| hex::encode(encrypted.to_be_bytes(RADIX, email_length)))
            })
            .unwrap_or(plaintext.to_string())
    }

    /// Either encrypt or decrypt data with AES256-CBC.
    pub fn aes(&self, action: Action, data: Vec<u8>) -> Result<String> {
        let key = GenericArray::from_slice(&self.key);

        match action {
            Action::Encrypt => {
                let iv = self.iv();

                let mut message = iv.to_vec();
                message.extend(
                    Aes256CbcEnc::new(key, &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&data),
                );

                Ok(hex::encode(message))
            }
            Action::Decrypt => {
                let data = hex::decode(data)?;
                let (iv, cipher_text) = data.split_at(16);
                let iv: [u8; 16] = iv.try_into()?;

                Ok(String::from_utf8(
                    Aes256CbcDec::new(key, &iv.into())
                        .decrypt_padded_vec_mut::<Pkcs7>(cipher_text)?,
                )?)
            }
        }
    }

    pub fn check_totp(
        &self,
        code: Option<String>,
        secret: &Option<String>,
    ) -> std::result::Result<(), ServerError> {
        if let Some(ref secret) = secret {
            let secret = self
                .aes(crate::crypto::Action::Decrypt, secret.as_bytes().to_vec())
                .map_err(|err| ServerError::Internal(err.to_string()))?;
            let mut errors = validator::ValidationErrors::new();

            if let Some(code) = code {
                if crate::totp::generate_totp(&secret, 30, 6).map_err(ServerError::Internal)?
                    != code
                {
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

    #[test]
    fn test_fpe_encryption() {
        const EMAIL: &str = "admin@gravitalia.com";

        let key = [0x42; 32];
        let cipher = Cipher::key(hex::encode(key)).unwrap();

        assert_eq!(
            cipher.format_preserving(EMAIL),
            "26378b206d60de2ed8819fc1bc9502ee2abcd7e1"
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
