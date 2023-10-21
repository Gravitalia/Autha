use serde::Serialize;

/// Represents the basic response message for warp.
#[derive(Serialize)]
pub struct Error {
    /// Field representing whether an error occurred.
    pub error: bool,
    /// In case of error, explain the error,
    /// else return "OK" or requested data.
    pub message: String,
}
