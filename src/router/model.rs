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
pub struct Login {
    pub email: String,
    pub password: String,
}

#[allow(dead_code)]
pub enum SecurityCode {
    Jwt,
    Email,
    Phone,
    Password,
}

#[derive(Serialize)]
pub struct User {
    pub username: String,
    pub vanity: String,
    pub avatar: Option<String>,
    pub bio: Option<String>,
    pub verified: bool,
    pub deleted: bool,
    pub flags: u32,
}