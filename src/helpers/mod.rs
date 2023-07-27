pub mod config_reader;
pub mod crypto;
pub mod grpc;
pub mod jwt;
pub mod ratelimiter;
pub mod request;
pub mod token;

use chrono::{Duration as ChronoDuration, NaiveDate, Utc};
use rand::RngCore;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Generate a random string
///
/// # Example
/// ```rust
/// let rand = random_string(16);
/// assert_eq!(rand.len(), 16);
/// ```
pub fn random_string(length: usize) -> String {
    let chars: Vec<char> =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&"
            .chars()
            .collect();
    let mut result = String::with_capacity(length);
    let mut rng = rand::thread_rng();

    for _ in 0..length {
        result.push(chars[rng.next_u32() as usize % 62]);
    }

    result
}

/// Get age with given data
/// ```rust
/// assert_eq!(get_age(2000, 01, 29), 23f64);
/// ```
pub fn get_age(year: i32, month: u32, day: u32) -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(date) => (((date.as_millis()
            - NaiveDate::from_ymd_opt(year, month, day)
                .unwrap()
                .and_hms_milli_opt(0, 0, 0, 0)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
                .timestamp_millis() as u128)
            / 31540000000) as f64)
            .floor(),
        Err(_) => 0.0,
    }
}

/// Check every day at 00h00 if users need to be deleted
pub async fn remove_deleted_account(scylla: std::sync::Arc<scylla::Session>) {
    tokio::task::spawn(async move {
        loop {
            let now = Utc::now();
            let time = (now.naive_utc().date().and_hms_opt(0, 0, 0).unwrap()
                + ChronoDuration::days(1))
            .timestamp()
                - now.timestamp();
            std::thread::sleep(Duration::from_secs(time as u64));

            if let Ok(x) = crate::database::scylla::query(Arc::clone(&scylla), format!("SELECT vanity FROM accounts.users WHERE expire_at >= '{}' ALLOW FILTERING", now.format("%Y-%m-%d+0000")), []).await {
                let res = x.rows.unwrap_or_default();

                for acc in res.iter() {
                    let _ = crate::database::scylla::query(Arc::clone(&scylla), "UPDATE accounts.users SET email = '', password = '', phone = '', birthdate = '', avatar = '', bio = '', banner = '', mfa_code = '', username = '' WHERE vanity = ?", vec![acc.columns[0].as_ref().unwrap().as_text().unwrap()]).await;
                }
            };
        }
    });
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
