use base32::decode;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generates a TOTP code.
pub fn generate_totp(secret: &str, time_step: u64, digits: u32) -> Result<String, String> {
    let key = decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
        .ok_or("Invalid base32 encoding")?;

    let time_counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs()
        / time_step;

    let counter_bytes = time_counter.to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).map_err(|_| "HMAC error")?;
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
