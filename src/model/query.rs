use serde::Deserialize;

/// Query struct for suspend account
#[derive(Deserialize)]
pub struct Suspend {
    pub vanity: String,
    pub suspend: Option<bool>,
}
