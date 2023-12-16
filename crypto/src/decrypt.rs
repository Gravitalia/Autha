use anyhow::Result;
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};
use ring::aead::*;

/// Decrypts the provided data using the CHACHA20_POLY1305 algorithm.
/// Returns the decrypted data as a string, or default string if decryption fails.
pub fn chacha20_poly1305(
    nonce: [u8; 12],
    mut data: Vec<u8>,
) -> Result<String, std::string::FromUtf8Error> {
    // Get CHACHA20 key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("CHACHA20_KEY").unwrap_or_default();
    let key_bytes: &[u8] = if key.is_empty() {
        &[0; 32]
    } else {
        key.as_bytes()
    };

    let mut opening_key = {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes).unwrap();
        let nonce_gen = crate::encrypt::NonceGen::new(nonce);
        OpeningKey::new(key, nonce_gen)
    };

    match opening_key.open_in_place(Aad::empty(), &mut data) {
        Ok(res) => String::from_utf8(res.to_vec()),
        Err(_) => {
            log::error!(
                "Cannot decrypt ChaCha20-Poly1205 data, got an error during opening. Have you decoded hex before call the function?"
            );

            Ok("".to_string())
        }
    }
}

/// Decrypts the provided data using the Format-preserving encryption
/// with FF1 and AES256.
pub fn format_preserving_encryption(data: Vec<u16>) -> Result<String> {
    // Get encryption key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let mut key = std::env::var("AES256_KEY").unwrap_or_default();
    if key.is_empty() {
        key = "4D6A514749614D6C74595A50756956446E5673424142524C4F4451736C515233".to_string();
    }

    let length = data.len();

    let ff = FF1::<aes::Aes256>::new(&hex::decode(key)?, 256)?;

    let decrypt = ff.decrypt(&[], &FlexibleNumeralString::from(data))?;

    Ok(String::from_utf8_lossy(&decrypt.to_be_bytes(256, length)).to_string())
}
