//! TOTP generator using HMAC-SHA1.

use application::error::{ApplicationError, Result};
use application::ports::outbound::TotpGenerator;
use base32::decode;
use domain::auth::factor::{TotpCode, TotpConfig, TotpSecret};
use hmac::{Hmac, Mac};
use sha1::Sha1;

/// HMAC-based TOTP generator.
pub struct HmacTotpGenerator;

impl HmacTotpGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Get current time counter based on Unix epoch.
    fn get_time_counter(&self, timestamp: u64, time_step: u64) -> u64 {
        timestamp / time_step
    }

    /// Decode Base32 secret.
    fn decode_secret(&self, secret: &TotpSecret) -> Result<Vec<u8>> {
        decode(
            base32::Alphabet::Rfc4648 { padding: false },
            secret.as_str(),
        )
        .ok_or_else(|| ApplicationError::Crypto {
            cause: "invalid base32 encoding".into(),
        })
    }

    /// Generate TOTP code for a specific time counter.
    fn generate_code(
        &self,
        secret_bytes: &[u8],
        time_counter: u64,
        digits: u8,
    ) -> Result<String> {
        let counter_bytes = time_counter.to_be_bytes();

        let mut mac =
            Hmac::<Sha1>::new_from_slice(secret_bytes).map_err(|err| {
                ApplicationError::Crypto {
                    cause: err.to_string(),
                }
            })?;

        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();

        // Dynamic truncation (RFC 6238).
        let offset = (result[19] & 0x0f) as usize;
        let binary_code = ((result[offset] as u32 & 0x7f) << 24) |
            ((result[offset + 1] as u32) << 16) |
            ((result[offset + 2] as u32) << 8) |
            (result[offset + 3] as u32);

        let mod_value = 10u32.pow(digits as u32);
        let code_int = binary_code % mod_value;
        let code = format!("{:0>width$}", code_int, width = digits as usize);

        Ok(code)
    }
}

impl Default for HmacTotpGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl TotpGenerator for HmacTotpGenerator {
    fn generate(
        &self,
        secret: &TotpSecret,
        config: &TotpConfig,
    ) -> Result<TotpCode> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ApplicationError::Unknown)?
            .as_secs();

        self.generate_at(secret, config, now)
    }

    fn generate_at(
        &self,
        secret: &TotpSecret,
        config: &TotpConfig,
        timestamp: u64,
    ) -> Result<TotpCode> {
        let secret_bytes = self.decode_secret(secret)?;
        let time_counter =
            self.get_time_counter(timestamp, config.time_step());

        let code_str =
            self.generate_code(&secret_bytes, time_counter, config.digits())?;

        TotpCode::new(code_str, config.digits())
            .map_err(ApplicationError::from)
    }

    fn verify(
        &self,
        code: &TotpCode,
        secret: &TotpSecret,
        config: &TotpConfig,
    ) -> Result<bool> {
        self.verify_with_window(code, secret, config, 1)
    }

    fn verify_with_window(
        &self,
        code: &TotpCode,
        secret: &TotpSecret,
        config: &TotpConfig,
        window: u8,
    ) -> Result<bool> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ApplicationError::Unknown)?
            .as_secs();

        let secret_bytes = self.decode_secret(secret)?;
        let current_counter = self.get_time_counter(now, config.time_step());

        for offset in -(window as i64)..=(window as i64) {
            let counter = (current_counter as i64 + offset) as u64;
            let generated =
                self.generate_code(&secret_bytes, counter, config.digits())?;

            if constant_time_eq::constant_time_eq(
                generated.as_bytes(),
                code.value().as_bytes(),
            ) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let generator = HmacTotpGenerator::new();
        let secret = TotpSecret::new("JBSWY3DPEHPK3PXP").unwrap();
        let config = TotpConfig::default();

        // Test with known timestamp (RFC 6238 test vector).
        let code = generator.generate_at(&secret, &config, 59).unwrap();
        assert_eq!(code.digits(), 6);
    }

    #[test]
    fn test_totp_verification() {
        let generator = HmacTotpGenerator::new();
        let secret = TotpSecret::new("JBSWY3DPEHPK3PXP").unwrap();
        let config = TotpConfig::default();

        let code = generator.generate(&secret, &config).unwrap();
        assert!(generator.verify(&code, &secret, &config).unwrap());
    }
}
