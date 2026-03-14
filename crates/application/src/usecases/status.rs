//! Status use case implementation.

use crate::dto::StatusDto;
use crate::ports::inbound::Status;

/// Status use case service.
pub struct StatusUseCase(&'static str);

impl StatusUseCase {
    pub fn new(configuration: StatusDto) -> Self {
        Self(Box::leak(Box::new(
            serde_json::json!(configuration).to_string(),
        )))
    }
}

impl Status for StatusUseCase {
    fn execute(&self) -> &'static str {
        self.0
    }
}
