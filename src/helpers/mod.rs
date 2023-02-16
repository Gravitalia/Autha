pub mod crypto;
pub mod jwt;

use std::time::{SystemTime, UNIX_EPOCH};
use chrono::prelude::*;
use rand::RngCore;

/// Generate a random string
/// ```rust
/// let rand = random_string(23);
/// assert_eq!(random_string(16).len(), 16);
/// ```
pub fn random_string(length: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&".chars().collect();
    let mut result = String::with_capacity(length);
    let mut rng = rand::thread_rng();

    for _ in 0..length {
        result.push(
            chars[rng.next_u32() as usize % 62],
        );
    }

    result
}

/// Get age with given data
/// ```rust
/// assert_eq!(get_age(2000, 01, 29), 23.0);
/// ```
pub fn get_age(year: i32, month: u32, day: u32) -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(date) => {
            (((date.as_millis()
            - NaiveDate::from_ymd_opt(year, month, day).unwrap().and_hms_milli_opt(0, 0, 0, 0).unwrap().and_local_timezone(Utc).unwrap().timestamp_millis() as u128)
            / 31540000000) as f64).floor()
        },
        Err(_) => 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_random_string() {
        assert_eq!(random_string(16).len(), 16);
    }

    #[tokio::test]
    async fn test_get_age() {
        assert_eq!(get_age(2000, 1, 29), 23f64);
    }
}