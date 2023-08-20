pub mod config_reader;
pub mod crypto;
pub mod grpc;
pub mod jwt;
pub mod ratelimiter;
pub mod request;
pub mod token;

use rand::RngCore;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
pub fn get_age(year: i16, month: i8, day: i8) -> i32 {
    // Calculating duration since the UNIX era
    let duration_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    // Converting time into seconds since the UNIX era
    let seconds_since_epoch = duration_since_epoch.as_secs();

    // Calculate the number of days spent
    let days_since_epoch = seconds_since_epoch / (60 * 60 * 24);

    // Calculate the year, month and day based on the number of days past
    let years_since_epoch: i16 = (1970 + days_since_epoch / 365)
        .try_into()
        .unwrap_or_default();
    let days_in_year = days_since_epoch % 365;
    let mut current_month: i8 = 0;
    let mut current_day: i8 = 0;
    let days_in_months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    // Find the current month and day based on days passed in the year
    for (i, &days_in_month) in days_in_months.iter().enumerate() {
        if days_in_year < days_in_month {
            current_month = i as i8 + 1;
            current_day = days_in_year as i8 + 1;
            break;
        }
    }

    // Compare birthdate with current date
    if year > years_since_epoch
        || (year == years_since_epoch && month > current_month)
        || (year == years_since_epoch
            && month == current_month
            && day > current_day)
    {
        0
    } else {
        let mut age = years_since_epoch - year;

        if month > current_month
            || (month == current_month && day > current_day)
        {
            age -= 1;
        }

        age.into()
    }
}

/// Check every day at 00h00 if users need to be deleted
pub async fn remove_deleted_account(scylla: std::sync::Arc<scylla::Session>) {
    tokio::task::spawn(async move {
        loop {
            let now = SystemTime::now();

            std::thread::sleep(Duration::from_secs(
                86400
                    - (now
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        % 86400),
            ));

            if let Ok(x) = crate::database::scylla::query(&scylla.clone(), format!("SELECT vanity FROM accounts.users WHERE expire_at >= '{}' ALLOW FILTERING", now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()), []).await {
                let res = x.rows.unwrap_or_default();

                for acc in res.iter() {
                    let _ = crate::database::scylla::query(&scylla, "UPDATE accounts.users SET email = '', password = '', phone = '', birthdate = '', avatar = '', bio = '', banner = '', mfa_code = '', username = '' WHERE vanity = ?", vec![acc.columns[0].as_ref().unwrap().as_text().unwrap()]).await;
                }
            };
        }
    });
}

/// Set a certain timestamp to a human readble one using RFC3339
pub fn format_rfc3339(timestamp: u64) -> String {
    let formatted = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        1970 + timestamp / 31556926, // Years (approximate number of seconds in a year)
        (timestamp / 2629743) % 12 + 1, // Months (approximate number of seconds in a month)
        (timestamp / 86400) % 30 + 1, // Days (approximate number of seconds in a day)
        (timestamp / 3600) % 24,      // Hours
        (timestamp / 60) % 60,        // Minutes
        timestamp % 60                // Seconds
    );

    formatted
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
        assert_eq!(get_age(2000, 1, 29), 23);
    }
}
