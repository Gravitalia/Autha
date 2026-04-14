//! Email logic management.

use std::fmt::Debug;

use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Result;

const MAX_EMAIL_LENGTH: usize = 254;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmailError {
    #[error("email format is not valid")]
    InvalidFormat,
    #[error("email exceeds 254 characters")]
    TooLong,
    #[error("string is empty")]
    Empty,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EmailAddress {
    bytes: [u8; MAX_EMAIL_LENGTH],
    len: u8,
}

impl EmailAddress {
    /// Converts a [`str`] into a valid [`EmailAddress`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string is not a valid email address.
    pub fn parse(email: &str) -> Result<Self> {
        if email.len() > MAX_EMAIL_LENGTH * 2 {
            return Err(EmailError::TooLong.into());
        }

        let normalized: String = email.nfc().collect();
        let normalized_lower = normalized.to_lowercase();

        Self::validate(normalized_lower.as_bytes())?;

        let bytes = normalized_lower.as_bytes();
        let n = bytes.len();

        if n > MAX_EMAIL_LENGTH {
            return Err(EmailError::TooLong.into());
        }

        let mut storage = [0u8; MAX_EMAIL_LENGTH];
        storage[..n].copy_from_slice(bytes);

        Ok(Self {
            bytes: storage,
            len: n as u8,
        })
    }

    fn validate<T: AsRef<[u8]>>(email: T) -> Result<()> {
        let bytes = email.as_ref();
        let bytes_len = bytes.len();

        if bytes_len < 5 {
            return Err(EmailError::Empty.into());
        }
        if bytes_len > MAX_EMAIL_LENGTH {
            return Err(EmailError::TooLong.into());
        }

        let mut parts = bytes.rsplitn(2, |&b| b == b'@');
        let domain_part = parts.next().ok_or(EmailError::InvalidFormat)?;
        let local_part = parts.next().ok_or(EmailError::InvalidFormat)?;

        if !Self::is_valid_local(local_part)
            || !Self::is_valid_domain(domain_part)
        {
            return Err(EmailError::InvalidFormat.into());
        }

        Ok(())
    }

    fn is_valid_local(local: &[u8]) -> bool {
        if local.is_empty() || local.len() > 64 {
            return false;
        }

        let mut last_was_dot = true;
        for &b in local {
            if b == b'.' {
                if last_was_dot {
                    return false;
                }
                last_was_dot = true;
            } else if b.is_ascii_alphanumeric()
                || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
                || b >= 128
            {
                last_was_dot = false;
            } else {
                return false;
            }
        }
        !last_was_dot
    }

    fn is_valid_domain(domain: &[u8]) -> bool {
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        let mut labels_count = 1;
        for &b in domain {
            if b == b'.' {
                labels_count += 1;
            }
        }

        if labels_count < 2 {
            return false;
        }

        for (i, label) in domain.split(|&b| b == b'.').enumerate() {
            if label.is_empty()
                || label.starts_with(b"-")
                || label.ends_with(b"-")
            {
                return false;
            }

            if i == labels_count - 1 {
                if label.len() < 2
                    || !label
                        .iter()
                        .all(|&b| b.is_ascii_alphabetic() || b >= 128)
                {
                    return false;
                }
            } else if !label
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b >= 128)
            {
                return false;
            }
        }
        true
    }

    /// Returns the same string as a string slice `&str`.
    #[inline]
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.as_bytes())
            .map_err(|_| EmailError::InvalidFormat.into())
    }

    /// Converts a string slice to a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl std::fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailAddress")
            .field("email", &"[REDACTED]")
            .finish()
    }
}

/*#[cfg(kani)]
mod proof {
    use super::*;
    use crate::error::DomainError;

    #[kani::proof]
    #[kani::unwind(257)]
    fn prove_email_validation_robustness() {
        let bytes: [u8; 256] = kani::any();
        let len: usize =
            kani::any_where(|&l| (l <= 8) || (l >= 253 && l <= 256));

        let email_slice = &bytes[..len];

        match EmailAddress::validate(email_slice) {
            Ok(_) => {
                let total_len = email_slice.len();
                assert!(total_len >= 5 && total_len <= 254);
                assert!(email_slice.contains(&b'@'));
            },
            Err(e) => {
                if len < 5 {
                    assert!(matches!(
                        e,
                        DomainError::InvalidEmailFormat(EmailError::Empty)
                            | DomainError::InvalidEmailFormat(
                                EmailError::InvalidFormat
                            )
                    ));
                } else if len > 254 {
                    assert!(matches!(
                        e,
                        DomainError::InvalidEmailFormat(EmailError::TooLong)
                    ));
                }
            },
        }
    }
}
*/
