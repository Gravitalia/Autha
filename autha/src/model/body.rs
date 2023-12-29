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
