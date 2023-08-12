use serde::Deserialize;

/// Represents the request body structure for the "create" route.
#[derive(Deserialize, Clone)]
pub struct Create {
    pub username: String,
    pub vanity: String,
    pub email: String,
    pub password: String,
    pub birthdate: Option<String>,
    pub phone: Option<String>,
}

/// Represents the request body structure for the login route.
#[derive(Deserialize, Clone)]
pub struct Login {
    pub email: String,
    pub password: String,
    pub mfa: Option<String>,
}

/// Represents the possible modifications for a user in the "UserPatch" context.
#[derive(Deserialize)]
pub struct UserPatch {
    pub username: Option<String>,
    pub avatar: Option<Vec<u8>>,
    pub bio: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub newpassword: Option<String>,
    pub birthdate: Option<String>,
    pub phone: Option<String>,
    pub mfa: Option<String>,
}

/// Represents the information required for GDPR compliance ("Gdrp").
#[derive(Deserialize)]
pub struct Gdrp {
    pub password: String,
    pub security_token: String,
}

/// Represents the parameters for OAuth authentication.
#[derive(Deserialize)]
pub struct OAuth {
    pub response_type: String,
    pub bot_id: String,
    pub redirect_uri: String,
    pub scope: String,
}

/// Represents the information to obtain an OAuth authentication token.
#[derive(Deserialize)]
pub struct GetOAuth {
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub redirect_uri: String,
}

/// Represents a temporary token with optional password and MFA fields.
#[derive(Deserialize)]
pub struct TempToken {
    pub password: Option<String>,
    pub mfa: Option<String>,
}
