use serde::Deserialize;

#[derive(Deserialize)]
pub struct Suspend {
    pub vanity: String
}
