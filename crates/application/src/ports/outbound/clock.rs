//! Clock port - Interface for time operations.

/// Port for getting the current time.
pub trait Clock: Send + Sync {
    /// Get the current Unix timestamp in seconds.
    fn now(&self) -> u64;

    /// Get the current Unix timestamp in milliseconds.
    fn now_millis(&self) -> u128;
}
