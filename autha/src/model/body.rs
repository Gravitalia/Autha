use serde::Deserialize;

/// Represents the body structure for creating a new user via HTTP route.
#[derive(Deserialize)]
pub struct Create {
    /// The name used for the account.
    pub username: String,
    /// Unique string associated to the user. It allows to identify a user.
    pub vanity: String,
    /// The email address associated with the user.
    pub email: String,
    /// Password to connect later to the account.
    pub password: String,
    /// ISO 639-1 language code.
    pub locale: String,
    /// The optional birthdate of the user, if available.
    pub birthdate: Option<String>,
    /// The optional phone number associated with the user, if available.
    /// Can be used to recover the account if the 2FA is forgotten.
    pub phone: Option<String>,
}

/// Represents the body structure for login via HTTP route.
#[derive(Deserialize)]
pub struct Login {
    /// Email address associated with the user.
    pub email: String,
    /// Personal account password.
    pub password: String,
    /// 6-digit multifactor authentication code.
    pub mfa: Option<String>,
}

/// Represents the body structure for user patch via HTTP route.
#[derive(Deserialize)]
pub struct UserPatch {
    /// The newname used of the account.
    pub username: Option<String>,
    /// Image buffer used as avatar.
    pub avatar: Option<Vec<u8>>,
    /// New biography of the account.
    pub bio: Option<String>,
    /// New email of the account.
    /// Require password field.
    pub email: Option<String>,
    /// Actual password of the user.
    pub password: Option<String>,
    /// New password of the account.
    /// Require password field.
    pub new_password: Option<String>,
    /// Update the birthdate of the user.
    pub birthdate: Option<String>,
    /// Update user's phone.
    pub phone: Option<String>,
    /// Update 2FA code used for login.
    /// Require password field.
    pub mfa: Option<String>,
}

/// Represents the body structure for creating an access token.
#[derive(Deserialize)]
pub struct OAuth {
    /// The unique identifier (vanity) for the application (bot).
    /// Required when `grant_type` is set to `authorization_code` or `client_credentials`.
    pub client_id: Option<String>,
    /// The secret key of the application (bot).
    /// Required when `grant_type` is set to `authorization_code` or `client_credentials`.
    pub client_secret: Option<String>,
    /// The temporary authorization code previously generated.
    /// Required when `grant_type` is set to `authorization_code`.
    pub code: Option<String>,
    /// The unhashed code used for Proof Key for Code Exchange (PKCE).
    /// If applicable.
    pub code_verifier: Option<String>,
    /// The type of grant being requested.
    /// Must be: `authorization_code` or `refresh_token`.
    pub grant_type: String,
    /// Redirect URL to be followed by the user.
    /// Required when `grant_type` is set to `authorization_code`.
    pub redirect_uri: Option<String>,
    /// Refresh code.
    /// Required when `grant_type` is set to `refresh_token`.
    pub refresh_token: Option<String>,
    /// Bot access granted by the user.
    pub scope: Option<String>,
}

/// Represents the body structure for revoke access token and refresh token.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct Revoke {
    /// Access token or refresh token.
    /// One of the two must be used to revoke the both.
    pub token: String,
    /// Should be access_token or refresh_token.
    /// Due to automatic detection, it is not necessary to use it.
    refresh_token: Option<String>,
}
