//! Status use case port.

/// Inbound port for status request.
pub trait Status: Send + Sync {
    /// Send current instance status.
    fn execute(&self) -> &'static str;
}
