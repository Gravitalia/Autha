use serde::Serialize;

/// Represents the body structure for creating a new user via HTTP route.
#[derive(Serialize)]
pub struct Token {
    /// Unique string associated to the user.
    pub vanity: String,
    /// Private and critical token that allows user to update account and connect everywhere.
    pub(crate) token: String,
    /// Account settings to keep services consistent.
    pub user_settings: super::config::UserSettings,
}

/// Represents the body structure for creating a new access token for OAuth2.
#[derive(Serialize)]
pub struct AccessToken {
    /// Token to access granted data.
    pub access_token: String,
    /// access_token validity period.
    pub expires_in: u64,
    /// Token to recreate an acces_token.
    pub refresh_token: String,
    /// refresh_token validity period.
    pub refresh_token_expires_in: u64,
    /// List of accesses granted.
    pub scope: String,
}
