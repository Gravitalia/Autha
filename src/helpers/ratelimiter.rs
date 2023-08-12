use std::collections::HashMap;
use std::time::{Duration, Instant};

// Define the rate limiter configuration
const WINDOW_SIZE: u64 = 60; // Window size in seconds
const MAX_REQUESTS: u64 = 100_000_000; // Maximum allowed requests within the window

// Define a data structure to hold the sliding window counter for each IP
#[derive(Default, Clone)]
pub struct RateLimiter {
    counters: HashMap<String, Vec<Instant>>,
    window_size: u64,
    max_requests: u64,
}

impl RateLimiter {
    pub fn new(window_size: Option<u64>, max_requests: Option<u64>) -> Self {
        RateLimiter {
            counters: HashMap::new(),
            window_size: if let Some(num) = window_size {
                num
            } else {
                WINDOW_SIZE
            },
            max_requests: if let Some(num) = max_requests {
                num
            } else {
                MAX_REQUESTS
            },
        }
    }

    pub fn check_rate(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        let window_start = now - Duration::from_secs(self.window_size);

        // Remove old entries from the sliding window
        if let Some(counter) = self.counters.get_mut(ip) {
            counter.retain(|&timestamp| timestamp > window_start);
        }

        // Check if the number of requests in the window has exceeded the limit
        if let Some(counter) = self.counters.get(ip) {
            if counter.len() as u64 >= self.max_requests {
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
