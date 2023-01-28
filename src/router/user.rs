use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub vanity: String,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub verified: bool,
    pub deleted: bool,
    pub flags: u32,
}