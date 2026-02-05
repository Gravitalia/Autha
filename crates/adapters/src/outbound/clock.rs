//! Time adapters.
//!
//! Code crash if there is a physical inconsistency (unrecoverable state).

use application::ports::outbound::Clock;

/// System clock using the OS time.
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs()
    }

    fn now_millis(&self) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_millis()
    }
}

#[cfg(test)]
pub struct FixedClock {
    timestamp: u64,
}

#[cfg(test)]
impl FixedClock {
    pub fn new(timestamp: u64) -> Self {
        Self { timestamp }
    }
}

#[cfg(test)]
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.timestamp
    }

    fn now_millis(&self) -> u128 {
        (self.timestamp * 1000) as u128
    }
}
