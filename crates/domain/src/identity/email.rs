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
        Self::validate(&normalized.to_lowercase())?;

        let bytes = normalized.as_bytes();
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

    fn validate(email: &str) -> Result<()> {
        let bytes_len = email.len();

        if bytes_len < 5 {
            return Err(EmailError::Empty.into());
        }
        if bytes_len > MAX_EMAIL_LENGTH {
            return Err(EmailError::TooLong.into());
        }

        let parts: Vec<&str> = email.rsplitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(EmailError::InvalidFormat.into());
        }

        let domain_part = parts[0];
        let local_part = parts[1];

        if !Self::is_valid_local(local_part)
            || !Self::is_valid_domain(domain_part)
        {
            return Err(EmailError::InvalidFormat.into());
        }

        Ok(())
    }

    fn is_valid_local(local: &str) -> bool {
        if local.is_empty() || local.len() > 64 {
            return false;
        }

        let mut last_was_dot = true;
        for c in local.chars() {
            if c == '.' {
                if last_was_dot {
                    return false;
                }
                last_was_dot = true;
            } else if c.is_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c)
            {
                last_was_dot = false;
            } else {
                return false;
            }
        }
        !last_was_dot
    }

    fn is_valid_domain(domain: &str) -> bool {
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return false;
        }

        for (i, label) in labels.iter().enumerate() {
            if label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
            {
                return false;
            }

            if i == labels.len() - 1
                && (label.len() < 2
                    || !label.chars().all(|c| c.is_alphabetic()))
            {
                return false;
            }

            if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
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

#[cfg(kani)]
mod proof {
    use super::*;

    #[kani::proof]
    #[kani::unwind(257)]
    fn prove_email_validation_robustness() {
        let bytes = kani::vec::any_vec::<u8, 256>();

        if let Ok(s) = std::str::from_utf8(&bytes) {
            match EmailAddress::validate(s) {
                Ok(_) => {
                    let total_len = s.len();
                    assert!(total_len >= 5 && total_len <= 254);
                    assert!(s.contains('@'));
                },
                Err(_) => {},
            }
        }
    }
}
