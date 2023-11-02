use anyhow::Result;
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
        let nonce_gen = crate::encrpt::NonceGen::new(nonce);
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
