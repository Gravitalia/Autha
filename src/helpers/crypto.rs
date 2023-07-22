use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit, OsRng}, XChaCha20Poly1305};
use fpe::ff1::{FF1, FlexibleNumeralString, Operations};
use crate::database::scylla::{create_salt, query};
use argon2::{Config, ThreadMode, Variant, Version};
use generic_array::GenericArray;
use scylla::Session;
use std::sync::Arc;
use anyhow::Result;

/// Hash data in bytes using Argon2id
pub fn hash(data: &[u8]) -> String {
    argon2::hash_encoded(
        data,
        super::random_string(16).as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: std::env::var("MEMORY_COST").unwrap_or_default().parse::<u32>().unwrap_or(524288),
            time_cost: std::env::var("ROUND").unwrap_or_default().parse::<u32>().unwrap_or(1),
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: std::env::var("KEY").expect("Missing env `KEY`").as_bytes(),
            ad: &[],
            hash_length: std::env::var("HASH_LENGTH").unwrap_or_default().parse::<u32>().unwrap_or(32)
        }
    ).unwrap()
}

/// Test if the password is corresponding with another one hashed
pub fn hash_test(hash: &str, pwd: &[u8]) -> bool {
    argon2::verify_encoded_ext(hash, pwd, std::env::var("KEY").expect("Missing env `KEY`").as_bytes(), &[]).unwrap_or(false)
}

/// Encrypt data as bytes into String with ChaCha20 (Salsa20) and Poly1305 
pub async fn encrypt(scylla: Arc<Session>, data: &[u8]) -> String {
    match hex::decode(std::env::var("CHA_KEY").expect("Missing env `CHA_KEY`")) {
        Ok(v) => {
            let bytes = GenericArray::clone_from_slice(&v);

            let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
            match XChaCha20Poly1305::new(&bytes).encrypt(&nonce, data) {
                Ok(y) => format!("{}//{}", create_salt(scylla, hex::encode(nonce)).await, hex::encode(y)),
                Err(_) => "Error".to_string(),
            }
        },
        Err(_) => "Error".to_string(),
    }
}

/// Decrypt a string with ChaCha20 (Salsa20) and Poly1305
pub async fn decrypt(scylla: Arc<Session>, data: String) -> Result<String> {
    println!("data: {}", data);
    let (salt, cypher) = data.split_once("//").unwrap_or(("", ""));

    let bytes = GenericArray::clone_from_slice(&hex::decode(std::env::var("CHA_KEY").expect("Missing env `CHA_KEY`"))?);
    let binding = hex::decode(
            &query(
                scylla,
                "SELECT salt FROM accounts.salts WHERE id = ?",
                vec![salt.to_string()]
            ).await?
            .rows
            .unwrap_or_default()[0]
            .columns[0]
            .as_ref()
            .unwrap()
            .as_text()
            .unwrap()
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

    let ff = FF1::<aes::Aes256>::new(&hex::decode(std::env::var("AES_KEY").expect("Missing env `AES_KEY`"))?, 256)?;
    Ok(hex::encode(ff.encrypt(&[], &FlexibleNumeralString::from(data))?.to_be_bytes(256, length)))
}

/// Decrypt hex string to clear string value, using FPE
pub fn fpe_decrypt(data: String) -> Result<String> {
    let data_to_vec: Vec<u16> = hex::decode(data)?.iter().map(|&x| x as u16).collect();
    let length_data = data_to_vec.len();

    let ff = FF1::<aes::Aes256>::new(&hex::decode(std::env::var("AES_KEY").expect("Missing env `AES_KEY`"))?, 256)?;
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
