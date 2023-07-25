use scylla::macros::FromRow;
use serde::{Deserialize, Serialize};

// Represents user as saved in database
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

// Represents tokens required to connect
#[derive(Serialize, Debug, Default, FromRow)]
pub struct Token {
    pub ip: String,
    pub date: i64,
    pub expire_at: i64,
    pub deleted: bool,
}

// Represents all datas that can be sent to users
#[derive(Serialize)]
pub struct UserData {
    pub user: User,
    pub tokens: Vec<Token>,
}
