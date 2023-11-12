use crate::random_string;
use anyhow::Result;
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};
use rand::{rngs::OsRng, RngCore};
use ring::aead::*;
use std::num::Wrapping;

/// A generator for producing nonces.
pub(crate) struct NonceGen {
    /// The current nonce value, wrapped to handle overflow.
    current: Wrapping<u128>,
    /// The initial value of the nonce generator.
    start: u128,
}

impl NonceGen {
    /// Creates a new NonceGen instance with the provided 12-byte start value.
    pub fn new(start: [u8; 12]) -> Self {
        let mut array = [0; 16];
        array[..12].copy_from_slice(&start);
        let start = u128::from_le_bytes(array);
        Self {
            current: Wrapping(start),
            start,
        }
    }
}

impl NonceSequence for NonceGen {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        // ! Warning: doesn't check u128 overflow correctly
        // Also, ring docs explicitly call this
        // out as "reasonable (but probably not ideal)"
        let n = self.current.0;
        self.current += 1;
        if self.current.0 == self.start {
            return Err(ring::error::Unspecified);
        }
        Ok(Nonce::assume_unique_for_key(
            n.to_le_bytes()[..12].try_into().unwrap(),
        ))
    }
}

/// Encrypts the provided data using the CHACHA20_POLY1305 algorithm.
/// Returns a tuple containing the nonce as a hexadecimal string and the encrypted data as a hexadecimal string.
pub fn chacha20_poly1305(mut data: Vec<u8>) -> Result<(String, String)> {
    // Get CHACHA20 key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("CHACHA20_KEY").unwrap_or_default();
    let key_bytes: &[u8] = if key.is_empty() {
        &[0; 32]
    } else {
        key.as_bytes()
    };

    // Generate crypto-secure 12 random bytes.
    let mut os_rng = OsRng;
    let mut nonce_seed = [0u8; 12];
    os_rng.fill_bytes(&mut nonce_seed);

    let mut sealing_key = {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes).unwrap();
        let nonce_gen = NonceGen::new(nonce_seed);
        SealingKey::new(key, nonce_gen)
    };

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .unwrap();

    Ok((hex::encode(nonce_seed), hex::encode(data)))
}

/// Encrypts data the provided data using (Format-preserving encryption)
/// and FF1 (Feistel-based Encryption Mode) with AES256.
pub fn format_preserving_encryption(data: Vec<u16>) -> Result<String> {
    // Get encryption key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let mut key = std::env::var("AES256_KEY").unwrap_or_default();
    if key.is_empty() {
        key = "4D6A514749614D6C74595A50756956446E5673424142524C4F4451736C515233".to_string();
    }

    let length = data.len();

    let ff = FF1::<aes::Aes256>::new(&hex::decode(key)?, 256)?;
    Ok(hex::encode(
        ff.encrypt(&[], &FlexibleNumeralString::from(data))?
            .to_be_bytes(256, length),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::chacha20_poly1305 as chacha20_poly1305_decrypt;

    #[test]
    fn test_chacha20_poly1305() {
        let plaintext = "2018-07-22";

        // Encrypt and get nonce and encrypted text.
        let (hex_nonce, encrypted) =
            chacha20_poly1305(plaintext.as_bytes().to_vec()).unwrap_or_default();

        // Convert nonce as hex to nonce in 12-bytes.
        let nonce: [u8; 12] = hex::decode(hex_nonce)
            .unwrap_or_default()
            .try_into()
            .unwrap_or_default();
        let decrypted =
            chacha20_poly1305_decrypt(nonce, hex::decode(encrypted).unwrap_or_default())
                .unwrap_or_default();

        assert_eq!(decrypted, plaintext.to_string())
    }
}
