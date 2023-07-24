use std::collections::HashMap;
use std::time::{Duration, Instant};

// Define the rate limiter configuration
const WINDOW_SIZE: u64 = 60; // Window size in seconds
const MAX_REQUESTS: u64 = 100; // Maximum allowed requests within the window

// Define a data structure to hold the sliding window counter for each IP
#[derive(Default, Clone)]
pub struct RateLimiter {
    counters: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            counters: HashMap::new(),
        }
    }

    pub fn check_rate(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        let window_start = now - Duration::from_secs(WINDOW_SIZE);

        // Remove old entries from the sliding window
        if let Some(counter) = self.counters.get_mut(ip) {
            counter.retain(|&timestamp| timestamp > window_start);
        }

        // Check if the number of requests in the window has exceeded the limit
        if let Some(counter) = self.counters.get(ip) {
            if counter.len() as u64 >= MAX_REQUESTS {
                return false;
            }
        }

        // Add the current request to the sliding window
        self.counters
            .entry(ip.to_string())
            .or_insert_with(Vec::new)
            .push(now);

        true
    }
}
