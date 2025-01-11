//! Cryptogragic logic.
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};

const RADIX: u32 = 256;

/// Encrypt email using FPE.
#[inline(always)]
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
