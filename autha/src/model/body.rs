use serde::Deserialize;

/// Represents the body structure for creating a new user via HTTP route.
#[derive(Deserialize, Clone)]
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
