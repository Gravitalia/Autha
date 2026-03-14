//! Status use case port.

use async_trait::async_trait;

/// Inbound port for status request.
#[async_trait]
pub trait Status: Send + Sync {
    /// Send current instance status.
    fn execute(&self) -> &'static str;
}
