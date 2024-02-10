#[cfg(feature = "format_preserving")]
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};
use ring::aead::*;
use crate::{CryptoError, RADIX};

/// Decrypts the provided data using the CHACHA20_POLY1305 algorithm.
/// Returns the decrypted data as a string, or default string if decryption fails.
pub fn chacha20_poly1305(
    nonce: [u8; 12],
    mut data: Vec<u8>,
) -> Result<String, CryptoError> {
    // Get CHACHA20 key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("CHACHA20_KEY").unwrap_or_default();
    let key_bytes: &[u8] = if key.is_empty() {
        &[0; 32]
    } else {
        key.as_bytes()
    };

    let mut opening_key = match UnboundKey::new(&CHACHA20_POLY1305, key_bytes) {
        Ok(key) => {
            let nonce_gen = crate::encrypt::NonceGen::new(nonce);
            OpeningKey::new(key, nonce_gen)
        }
        Err(_) => return Err(CryptoError::Unspecified),
    };

    match opening_key.open_in_place(Aad::empty(), &mut data) {
        Ok(res) => {
            String::from_utf8(res.to_vec()).map_err(|_| CryptoError::UTF8Error)
        }
        Err(_) => Err(CryptoError::Unspecified),
    }
}

/// Decrypts the provided data using the Format-preserving encryption
/// with FF1 and AES256.
#[cfg(feature = "format_preserving")]
pub fn format_preserving_encryption(data: Vec<u16>) -> Result<String, CryptoError> {
    // Get encryption key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("AES256_KEY").unwrap_or_else(|_| {
        "4D6A514749614D6C74595A50756956446E5673424142524C4F4451736C515233".to_string()
    });

    let key_bytes = hex::decode(&key).map_err(|_| CryptoError::UnableDecodeHex)?;

    let ff = FF1::<aes::Aes256>::new(&key_bytes, RADIX)
        .map_err(|_| CryptoError::InvalidRadix)?;

    let decrypt = ff.decrypt(&[], &FlexibleNumeralString::from(data.clone()))
        .map_err(|_| CryptoError::ExceedRadix)?;

    Ok(decrypt.to_be_bytes(RADIX, data.len()).iter().map(|&b| b as char).collect())
}
