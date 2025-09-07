use base32::decode;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, ServerError};

#[derive(Debug)]
struct Base32DecodeError();

impl std::fmt::Display for Base32DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid base32 encoding")
    }
}

impl std::error::Error for Base32DecodeError {}

/// Generates a TOTP code.
pub fn generate_totp(secret: &str, time_step: u64, digits: u32) -> Result<String> {
    let key = decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
        .ok_or(ServerError::ParsingForm(Box::new(Base32DecodeError())))?;

    let time_counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| ServerError::Internal {
            details: String::default(),
            source: Some(Box::new(err)),
        })?
        .as_secs()
        / time_step;

    let counter_bytes = time_counter.to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).map_err(|err| ServerError::Internal {
        details: String::default(),
        source: Some(Box::new(err)),
    })?;
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0x0f) as usize;
    let binary_code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let mut code = (binary_code % 10u32.pow(digits)).to_string();

    // Ensure the code has the correct number of digits.
    while code.len() < digits as usize {
        code.insert(0, '0');
    }

    Ok(code)
}
