use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit, OsRng}, XChaCha20Poly1305};
use fpe::ff1::{FF1, FlexibleNumeralString, Operations};
use crate::database::cassandra::{create_salt, query};
use argon2::{Config, ThreadMode, Variant, Version};
use generic_array::GenericArray;
use anyhow::Result;

/// Hash data in bytes using Argon2id
pub fn hash(data: &[u8]) -> String {
    argon2::hash_encoded(
        data,
        super::random_string(16).as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: dotenv::var("MEMORY_COST").unwrap_or_default().parse::<u32>().unwrap_or(524288),
            time_cost: dotenv::var("ROUND").unwrap_or_default().parse::<u32>().unwrap_or(1),
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: dotenv::var("KEY").expect("Missing env `KEY`").as_bytes(),
            ad: &[],
            hash_length: dotenv::var("HASH_LENGTH").unwrap_or_default().parse::<u32>().unwrap_or(32)
        }
    ).unwrap()
}

/// Test if the password is corresponding with another one hashed
pub fn hash_test(hash: &str, pwd: &[u8]) -> bool {
    argon2::verify_encoded_ext(hash, pwd, dotenv::var("KEY").expect("Missing env `KEY`").as_bytes(), &[]).unwrap_or(false)
}

/// Encrypt data as bytes into String with ChaCha20 (Salsa20) and Poly1305 
pub fn encrypt(data: &[u8]) -> String {
    match hex::decode(dotenv::var("CHA_KEY").expect("Missing env `CHA_KEY`")) {
        Ok(v) => {
            let bytes = GenericArray::clone_from_slice(&v);

            let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
            match XChaCha20Poly1305::new(&bytes).encrypt(&nonce, data) {
                Ok(y) => format!("{}//{}", create_salt(hex::encode(nonce)), hex::encode(y)),
                Err(_) => "Error".to_string(),
            }
        },
        Err(_) => "Error".to_string(),
    }
}

/// Decrypt a string with ChaCha20 (Salsa20) and Poly1305
pub fn decrypt(data: String) -> Result<String> {
    let (salt, cypher) = data.split_once("//").unwrap_or(("", ""));

    let bytes = GenericArray::clone_from_slice(&hex::decode(dotenv::var("CHA_KEY").expect("Missing env `CHA_KEY`"))?);
    let binding = hex::decode(
        std::str::from_utf8(
            &query(
                "SELECT salt FROM accounts.salts WHERE id = ?",
                vec![salt.to_string()]
            )?
            .get_body()?
            .as_cols()
            .unwrap()
            .rows_content
            .clone()[0][0]
            .clone()
            .into_plain()
            .unwrap()[..]
        )?
    )?;

    match XChaCha20Poly1305::new(&bytes).decrypt(GenericArray::from_slice(&binding), hex::decode(cypher)?.as_ref()) {
        Ok(y) => Ok(String::from_utf8(y)?),
        Err(e) => {
            eprintln!("(decrypt) cannot decrypt: {}", e);
            Ok("Error".to_string())
        }
    }
}

/// Encrypt data with FPE (Format-preserving encryption) and FF1 (Feistel-based Encryption Mode)
pub fn fpe_encrypt(data: Vec<u16>) -> Result<String> {
    let length = data.len();

    let ff = FF1::<aes::Aes256>::new(&hex::decode(dotenv::var("AES_KEY").expect("Missing env `AES_KEY`"))?, 256)?;
    Ok(hex::encode(ff.encrypt(&[], &FlexibleNumeralString::from(data))?.to_be_bytes(256, length)))
}

/// Decrypt hex string to clear string value, using FPE
pub fn fpe_decrypt(data: String) -> Result<String> {
    let data_to_vec: Vec<u16> = hex::decode(data)?.iter().map(|&x| x as u16).collect();
    let length_data = data_to_vec.len();

    let ff = FF1::<aes::Aes256>::new(&hex::decode(dotenv::var("AES_KEY").expect("Missing env `AES_KEY`"))?, 256)?;
    let decrypt = ff.decrypt(&[], &FlexibleNumeralString::from(data_to_vec))?;
    
    Ok(String::from_utf8_lossy(&decrypt.to_be_bytes(256, length_data)).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let pwd = &hash(b"password");
        assert!(regex::Regex::new(r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*").unwrap().is_match(pwd));
        assert!(hash_test(pwd, b"password"));
    }
}
