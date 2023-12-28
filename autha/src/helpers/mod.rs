pub mod config;
pub mod format;
pub mod machine_learning;
pub mod request;
pub mod token;

use std::time::{SystemTime, UNIX_EPOCH};

/// Get age with given year, month and day.
/// ```rust
/// assert_eq!(get_age(2000, 01, 29), 23f64);
/// ```
pub fn get_age(year: i16, month: i8, day: i8) -> anyhow::Result<i32> {
    // Calculating duration since the UNIX era
    let duration_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;

    // Calculate the number of days spent
    let days_since_epoch = duration_since_epoch.as_secs() / 86_400 - 12;

    // Calculate the year, month and day based on the number of days past
    let years_since_epoch: i16 = (1970 + days_since_epoch / 365)
        .try_into()
        .unwrap_or_default();
    let mut days_in_year = days_since_epoch % 365;
    let mut current_month = 0;
    let mut current_day = 0;
    let days_in_months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    // Find the current month and day based on days passed in the year
    for (i, &days_in_month) in days_in_months.iter().enumerate() {
        days_in_year -= days_in_month;

        if days_in_year <= days_in_month {
            current_month = i as i8 + 2;
            current_day = days_in_year.try_into()?;
            break;
        }
    }

    // Compare birthdate with current date
    if year > years_since_epoch
        || (year == years_since_epoch && month > current_month)
        || (year == years_since_epoch && month == current_month && day > current_day)
    {
        Ok(0)
    } else {
        let mut age = years_since_epoch - year;

        if month > current_month || (month == current_month && day > current_day) {
            age -= 1;
        }

        Ok(age.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_age() {
        assert_eq!(get_age(2000, 1, 29).unwrap(), 23);
    }
}
