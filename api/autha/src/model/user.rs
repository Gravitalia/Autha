use db::libscylla as scylla;
use db::libscylla::macros::FromRow;
use serde::{Deserialize, Serialize};

/// Represents the user details as saved in the databases.
#[derive(Serialize, Deserialize, FromRow, Debug, Default, Clone)]
pub struct User {
    /// The username of the user. Could be firstname and lastname.
    pub username: String,
    /// Unique and inalienable identifier to get a user.
    pub vanity: String,
    /// MD5 hash of the avatar dataURI.
    pub avatar: Option<String>,
    /// Short description of the user. Must not exceed 250 characters.
    pub bio: Option<String>,
    /// User's e-mail address.
    pub email: Option<String>,
    /// User's date of birth.
    pub birthdate: Option<String>,
    /// User's telephone number.
    pub phone: Option<String>,
    /// If the user's e-mail address has been verified:
    pub verified: bool,
    /// If the user has recently deleted their account or it has been suspended.
    pub deleted: bool,
    /// Bitfields representing the user's badges and privileges.
    pub flags: i32,
}

/// Represents the data contained in a token.
#[derive(Debug, Clone)]
pub struct Token {
    /// User or bot token.
    pub token: String,
    /// Unique and inalienable identifier of the user or bot.
    pub vanity: String,
    /// If it is a robot.
    pub is_bot: bool,
    /// In the case of OAuth 2.0 (Bearer token), list token accesses.
    pub scopes: Option<Vec<String>>,
}
