pub mod crypto;
pub mod jwt;
pub mod request;

use std::time::{SystemTime, UNIX_EPOCH, Duration};
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
/// assert_eq!(get_age(2000, 01, 29), 23f64);
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

/// Check every day at 00h00 if users need to be deleted
pub async fn remove_deleted_account() {
    tokio::task::spawn(async {
        loop {
            let now = chrono::Utc::now();
            let time = Utc.with_ymd_and_hms(now.year(), now.month(), now.day()+1, 0, 0, 0).unwrap().timestamp()-now.timestamp();
            std::thread::sleep(Duration::from_secs(time.try_into().unwrap_or_default()));

            match crate::database::cassandra::query(format!("SELECT vanity FROM accounts.users WHERE expire_at >= '{}' ALLOW FILTERING", (now+chrono::Duration::days(30)).format("%Y-%m-%d+0000").to_string()), vec![]) {
                Ok(x) => {
                    let res = x.get_body().unwrap().as_cols().unwrap().rows_content.clone();
    
                    for acc in res.iter() {
                        let _ = crate::database::cassandra::query("UPDATE accounts.users SET email = null, password = null, phone = null, birthdate = null, avatar = null, bio = null, banner = null, mfa_code = null, username = ?, expire_at = null WHERE vanity = ?",
                        vec!["".to_string(), std::str::from_utf8(&acc[0].clone().into_plain().unwrap()[..]).unwrap().to_string()]);
                    }
                },
                Err(_) => {}
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