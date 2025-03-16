//! Cryptogragic logic.
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey};

const RADIX: u32 = 256;

/// Encrypt email using FPE.
#[inline]
pub fn email_encryption(data: String) -> String {
    std::env::var("AES_KEY")
        .ok()
        .and_then(|key| hex::decode(&key).ok())
        .and_then(|key| FF1::<aes::Aes256>::new(&key, RADIX).ok())
        .and_then(|ff| {
            let email: Vec<u16> = data.encode_utf16().collect();
            let email_length = email.len();

            ff.encrypt(&[], &FlexibleNumeralString::from(email))
                .ok()
                .map(|encrypted| hex::encode(encrypted.to_be_bytes(RADIX, email_length)))
        })
        .unwrap_or(data)
}

#[derive(Debug, thiserror::Error)]
pub enum RsaError {
    #[error(transparent)]
    Pkcs1(#[from] rsa::pkcs1::Error),
    #[error(transparent)]
    Pkcs8(#[from] rsa::pkcs8::spki::Error),
    #[error("unknown public key format")]
    UnknownFormat,
}

/// Check if a key is well-formatted.
pub fn check_key(key: &str) -> Result<RsaPublicKey, RsaError> {
    if key.contains("BEGIN RSA PUBLIC KEY") {
        // Means it is PKCS-1.
        Ok(RsaPublicKey::from_pkcs1_pem(key).map_err(RsaError::Pkcs1)?)
    } else if key.contains("BEGIN PUBLIC KEY") {
        // Means it is PKCS-8.
        Ok(RsaPublicKey::from_public_key_pem(key).map_err(RsaError::Pkcs8)?)
    } else {
        Err(RsaError::UnknownFormat)
    }
}
