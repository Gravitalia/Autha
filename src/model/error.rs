use serde::Serialize;

#[derive(Serialize)]
pub struct Error {
    pub error: bool,
    pub message: String,
}