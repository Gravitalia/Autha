#![forbid(unsafe_code)]
#![deny(
    dead_code,
    unused_imports,
    unused_mut,
    missing_docs,
    missing_debug_implementations
)]

//! Local sliding windows rate limiting algorithm implementation.

/// Implement the rate-limiter on the `warp` library.
#[cfg(feature = "warp")]
pub mod warp;

use dashmap::DashMap;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Structure of a limiter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// The size of the window, the number of queries that can be performed in the given time.
    maximum_request: usize,
    /// Window duration.
    time: Duration,
    /// Entires. Each entry has its own rate-limit.
    buckets: DashMap<String, VecDeque<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter. This can be used for each route.
    ///
    /// # Example
    /// ```rust
    /// use autha_limits::RateLimiter;
    /// use std::time::Duration;
    ///
    /// let limiter = RateLimiter::new(10, Duration::from_secs(1)); // 10 requests per second.
    /// ```
    pub fn new(maximum_request: usize, time: Duration) -> Self {
        RateLimiter {
            maximum_request,
            time,
            buckets: DashMap::new(),
        }
    }

    /// Checks if a new request exceeds the limit. If not, increments the counter.
    pub fn check<T>(&self, key: T) -> bool
    where
        T: ToString,
    {
        let now = Instant::now();
        let mut ip_limits = self.buckets.entry(key.to_string()).or_default();

        // Clean old requests.
        while let Some(time) = ip_limits.front() {
            if now.duration_since(*time) > self.time {
                ip_limits.pop_front();
            } else {
                break;
            }
        }

        if ip_limits.len() >= self.maximum_request {
            false
        } else {
            ip_limits.push_back(now);
            true
        }
    }

    /// Reset all values from bucket.
    pub fn reset(&mut self) {
        self.buckets = DashMap::new();
    }
}

#[cfg(test)]
mod tests {
    use crate::RateLimiter;
    use std::{thread::sleep, time::Duration};

    const IP: &str = "0.0.0.0";
    const OTHER_IP: &str = "1.1.1.1";

    #[test]
    fn test_duration() {
        let limiter = RateLimiter::new(2, Duration::from_secs(5));

        // second 0.
        assert!(limiter.check(IP));

        // second 1.
        sleep(Duration::from_secs(1));
        assert!(limiter.check(IP));
        assert!(!limiter.check(IP)); // This request exceed limit.

        // second 5.
        // only one entry should have been decremented.
        sleep(Duration::from_secs(4));
        assert!(limiter.check(IP));
        assert!(!limiter.check(IP)); // This request exceed limit.
    }

    #[test]
    fn test_multiple_entires() {
        let limiter = RateLimiter::new(2, Duration::from_secs(1));

        // only IP is limited.
        assert!(limiter.check(IP));
        assert!(limiter.check(OTHER_IP));
        assert!(limiter.check(IP));
        assert!(!limiter.check(IP)); // ip is limited.
        assert!(limiter.check(OTHER_IP));
    }
}
