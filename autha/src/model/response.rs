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
