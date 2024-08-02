use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};

/// Compute the SHA256 digest for the bytes data.
///
/// # Examples
///
/// ```rust
/// use crypto::hash::sha::sha256;
///
/// let plaintext = "1234";
/// println!("{} is {} when hashed with SHA256", plaintext, sha256(plaintext.as_bytes()));
/// ```
pub fn sha256(data: &[u8]) -> String {
    let mut context = Context::new(&SHA256);

    context.update(data);

    hex::encode(context.finish())
}

/// Compute the SHA1 digest for the bytes data.
///
/// # Warning
/// This should only be used when security is not a priority.
///
/// # Examples
///
/// ```rust
/// use crypto::hash::sha::sha1;
///
/// let plaintext = "1234";
/// println!("{} is {} when hashed with SHA1", plaintext, sha1(plaintext.as_bytes()));
/// ```
pub fn sha1(data: &[u8]) -> String {
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);

    context.update(data);

    hex::encode(context.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"rainbow");

        assert_eq!(
            hash,
            "8fced00b6ce281456d69daef5f2b33eaf1a4a29b5923ebe5f1f2c54f5886c7a3"
                .to_string()
        );
    }

    #[test]
    fn test_sha1() {
        let hash = sha1(b"hello world!");

        assert_eq!(
            hash,
            "430ce34d020724ed75a196dfc2ad67c77772d169".to_string()
        );
    }
}
