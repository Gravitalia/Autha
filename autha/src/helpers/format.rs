/// Formats a UNIX timestamp into a human-readable string using RFC3339 format.
pub fn format_rfc3339(timestamp: u64) -> String {
    let formatted = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        1970 + timestamp / 31556926, // Years (approximate number of seconds in a year)
        (timestamp / 2629743) % 12 + 1, // Months (approximate number of seconds in a month)
        (timestamp / 86400) % 30 + 1, // Days (approximate number of seconds in a day)
        (timestamp / 3600) % 24,     // Hours
        (timestamp / 60) % 60,       // Minutes
        timestamp % 60               // Seconds
    );

    formatted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_rfc3339() {
        // Test with a known UNIX timestamp
        let timestamp = 1629636862;
        let formatted = format_rfc3339(timestamp);

        assert_eq!(formatted, "2021-08-22T12:54:22Z");
    }
}
