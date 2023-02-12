use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct Create {
    pub username: String,
    pub vanity: String,
    pub email: String,
    pub password: String,
    pub birthdate: Option<String>,
    pub phone: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct Login {
    pub email: String,
    pub password: String
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
    pub mfa: Option<String>
}

#[derive(Deserialize)]
pub struct OAuth {
    pub response_type: String,
    pub bot_id: String,
    pub redirect_uri: String,
    pub scope: String
}

#[derive(Deserialize)]
pub struct GetOAuth {
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub redirect_uri: String
}