use argon2::{self, Config, ThreadMode, Variant, Version};

/// Generate a random string
/// ```rust
/// let rand = random_string(23);
/// assert_eq!(random_string(16).len(), 16);
/// ```
pub fn random_string(length: i32) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".chars().collect();
    let mut result = String::default();

    unsafe {
        for _ in 0..length {
            result.push(
                *chars.get_unchecked(fastrand::usize(0..62))
            );
        }
    }

    result
}

/// Hash data in bytes using Argon2id
pub fn hash(data: &[u8]) -> String {
    argon2::hash_encoded(
        data,
        random_string(16).as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 1048576,
            time_cost: 10,
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: "aOLJ5k4PuXbOmQmfggM2qm82LtGCInz8Hn8qGEczZrYBcr5cRsrg860mPY4NA6Is".as_bytes(),
            ad: &[],
            hash_length: 32
        }
    ).unwrap()
}

/// Test if the password is corresponding with another one hashed
pub fn hash_test(hash: &str, pwd: &[u8]) -> bool {
    argon2::verify_encoded_ext(hash, pwd, "aOLJ5k4PuXbOmQmfggM2qm82LtGCInz8Hn8qGEczZrYBcr5cRsrg860mPY4NA6Is".as_bytes(), &[]).unwrap()
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

    #[tokio::test]
    async fn test_random_string() {
        assert_eq!(random_string(16).len(), 16);
    }
}