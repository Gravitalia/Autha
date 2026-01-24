//! Interface for observability.

/// Port for telemetry/observability operations.
pub trait TelemetryPort: Send + Sync {
    /// Record a successful authentication.
    fn record_auth_success(&self, user_id: &str, method: &str);

    /// Record a failed authentication attempt.
    fn record_auth_failure(&self, reason: &str);

    /// Record a new account creation.
    fn record_account_created(&self, user_id: &str);

    /// Increment a counter metric.
    fn increment_counter(&self, name: &str, labels: &[(&str, &str)]);

    /// Record a histogram observation.
    fn record_histogram(
        &self,
        name: &str,
        value: f64,
        labels: &[(&str, &str)],
    );
}
