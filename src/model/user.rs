use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct User {
    pub username: String,
    pub vanity: String,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub email: Option<String>,
    pub birthdate: Option<String>,
    pub verified: bool,
    pub deleted: bool,
    pub flags: u8,
    #[serde(skip_serializing)]
    pub(crate) password: Option<String>,
    #[serde(skip_serializing)]
    pub(crate) phone: Option<String>,
}