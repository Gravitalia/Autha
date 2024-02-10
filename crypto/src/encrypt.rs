use crate::{CryptoError, RADIX, random_bytes};
#[cfg(feature = "format_preserving")]
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};
use ring::aead::*;
use ring::error::Unspecified;
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
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        // ! Warning: doesn't check u128 overflow correctly
        // Also, ring docs explicitly call this
        // out as "reasonable (but probably not ideal)"
        let n = self.current.0;
        self.current += 1;
        if self.current.0 == self.start {
            return Err(Unspecified);
        }

        Ok(Nonce::assume_unique_for_key(
            n.to_le_bytes()[..12].try_into().unwrap_or_default(),
        ))
    }
}

/// Encrypts the provided data using the CHACHA20_POLY1305 algorithm.
/// Returns a tuple containing the nonce as a hexadecimal string and the encrypted data as a hexadecimal string.
pub fn chacha20_poly1305(
    mut data: Vec<u8>,
) -> Result<(String, String), Unspecified> {
    // Get CHACHA20 key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("CHACHA20_KEY").unwrap_or_default();
    let key_bytes: &[u8] = if key.is_empty() {
        &[0; 32]
    } else {
        key.as_bytes()
    };

    // Generate crypto-secure 12 random bytes.
    let nonce_seed: [u8; 12] =
        random_bytes(12).as_slice().try_into().unwrap_or_default();

    let mut sealing_key = {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes)?;
        let nonce_gen = NonceGen::new(nonce_seed);
        SealingKey::new(key, nonce_gen)
    };

    sealing_key.seal_in_place_append_tag(Aad::empty(), &mut data)?;

    Ok((hex::encode(nonce_seed), hex::encode(data)))
}

/// Encrypts data the provided data using (Format-preserving encryption)
/// and FF1 (Feistel-based Encryption Mode) with AES256.
#[cfg(feature = "format_preserving")]
pub fn format_preserving_encryption(
    data: Vec<u16>,
) -> Result<String, CryptoError> {
    // Get encryption key. The key MUST be 32 bytes (256 bits), otherwise it panics.
    let key = std::env::var("AES256_KEY").unwrap_or_else(|_| {
        "4D6a514749614D6c74595a50756956446e5673424142524c4f4451736c515233".to_string()
    });

    let key_bytes = hex::decode(&key).map_err(|_| CryptoError::UnableDecodeHex)?;

    let ff = FF1::<aes::Aes256>::new(&key_bytes, RADIX)
        .map_err(|_| CryptoError::InvalidRadix)?;

    let encrypted_data = ff.encrypt(&[], &FlexibleNumeralString::from(data.clone()))
        .map_err(|_| CryptoError::ExceedRadix)?;

    Ok(hex::encode(encrypted_data.to_be_bytes(RADIX, data.len())))
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
            chacha20_poly1305(plaintext.as_bytes().to_vec()).unwrap();

        // Convert nonce as hex to nonce in 12-bytes.
        let nonce: [u8; 12] =
            hex::decode(hex_nonce).unwrap().try_into().unwrap();
        let decrypted =
            chacha20_poly1305_decrypt(nonce, hex::decode(encrypted).unwrap())
                .unwrap();

        assert_eq!(decrypted, plaintext.to_string())
    }
}
