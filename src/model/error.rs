use serde::Serialize;

/// Represents basic message response
#[derive(Serialize)]
pub struct Error {
    pub error: bool,
    pub message: String,
}
