use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Error {
    pub error: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct Create {
    pub username: String,
    pub vanity: String,
    pub email: String,
    pub password: String,
    pub birthdate: Option<String>,
    pub phone: Option<String>,
}

#[derive(Serialize)]
pub struct CreateResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct UserPatch {
    pub username: Option<String>,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub newpassword: Option<String>,
    pub birthdate: Option<String>,
    pub phone: Option<String>,
}

#[derive(Deserialize)]
pub struct Login {
    pub email: String,
    pub password: String,
    pub mfa: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    pub user: Option<bool>
}

#[allow(dead_code)]
pub enum SecurityCode {
    Jwt,
    Email,
    Phone,
    Password,
}

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

#[derive(Deserialize)]
pub struct OAuth {
    pub response_type: String,
    pub bot_id: String,
    pub redirect_uri: String,
    pub scope: String
}