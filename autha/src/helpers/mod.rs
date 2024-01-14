pub mod config;
pub mod format;
pub mod machine_learning;
pub mod request;
pub mod telemetry;
pub mod token;

use anyhow::Result;
use chrono::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

const MILLIS_IN_YEAR: u128 = 31_556_952_000;

/// Get age with given year, month and day.
/// ```rust
/// assert_eq!(get_age(2000, 01, 29), 23f64);
/// ```
pub fn get_age(year: i16, month: i8, day: i8) -> Result<i32> {
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?;

    let birth_date = NaiveDate::from_ymd_opt(year.into(), month.try_into()?, day.try_into()?)
        .unwrap_or_default()
        .and_hms_milli_opt(0, 0, 0, 0)
        .unwrap_or_default()
        .and_local_timezone(Utc)
        .unwrap()
        .timestamp_millis() as u128;

    Ok(((current_time.as_millis() - birth_date) / MILLIS_IN_YEAR).try_into()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_age() {
        assert_eq!(get_age(2000, 1, 1).unwrap(), 24);
    }
}
