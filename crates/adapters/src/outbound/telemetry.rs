//! Telemetry adapters - Observability implementations.

use application::ports::outbound::TelemetryPort;

/// Tracing-based telemetry adapter.
#[derive(Default)]
pub struct TracingTelemetry;

impl TracingTelemetry {
    /// Create a new [`TracingTelemetry`].
    pub fn new() -> Self {
        Self
    }
}

impl TelemetryPort for TracingTelemetry {
    fn record_auth_success(&self, user_id: &str, method: &str) {
        tracing::info!(
            user_id = user_id,
            method = method,
            "authentication successful"
        );
    }

    fn record_auth_failure(&self, reason: &str) {
        tracing::info!(reason = reason, "authentication failed");
    }

    fn record_account_created(&self, user_id: &str) {
        tracing::info!(user_id = user_id, "account created");
    }

    fn increment_counter(&self, name: &str, labels: &[(&str, &str)]) {
        tracing::debug!(name = name, ?labels, "counter incremented");
    }

    fn record_histogram(
        &self,
        name: &str,
        value: f64,
        labels: &[(&str, &str)],
    ) {
        tracing::debug!(
            name = name,
            value = value,
            ?labels,
            "histogram recorded"
        );
    }
}
