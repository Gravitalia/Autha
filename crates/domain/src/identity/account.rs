//! Typed builder for `User`.

use crate::auth::password::PasswordHash;
use crate::identity::email::EmailAddress;
use crate::identity::id::UserId;
use crate::identity::user::User;

const DEFAULT_LOCALE: &str = "en";

/// Marker type for missing value.
#[derive(Debug)]
pub struct Missing;

/// Marker type for present value.
#[derive(Debug)]
pub struct Present<T>(pub T);

/// A builder to track presence of `Id` and `Email`.
#[derive(Debug)]
pub struct UserBuilder<Id, Email> {
    id: Id,
    username: String,
    email: Email,
    password: PasswordHash,
    locale: String,
    ip: Option<String>,
    invite: Option<String>,
}

impl UserBuilder<Missing, Missing> {
    /// Creates a new [`UserBuilder`] with all required fields initialized as
    /// [`Missing`].
    pub fn new() -> Self {
        Self {
            id: Missing,
            username: String::new(),
            email: Missing,
            password: PasswordHash::new(""),
            locale: DEFAULT_LOCALE.to_string(),
            ip: None,
            invite: None,
        }
    }
}

impl Default for UserBuilder<Missing, Missing> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Email> UserBuilder<Missing, Email> {
    /// Sets user identity using [`UserId`].
    pub fn id(self, id: UserId) -> UserBuilder<Present<UserId>, Email> {
        UserBuilder {
            id: Present(id),
            username: self.username,
            email: self.email,
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
        }
    }
}

impl<Id> UserBuilder<Id, Missing> {
    /// Sets user email using [`EmailAddress`] value object.
    pub fn email(
        self,
        email: EmailAddress,
    ) -> UserBuilder<Id, Present<EmailAddress>> {
        UserBuilder {
            id: self.id,
            username: self.username,
            email: Present(email),
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
        }
    }
}

impl<Id, Email> UserBuilder<Id, Email> {
    /// Sets the hashed password.
    pub fn password(mut self, password: PasswordHash) -> Self {
        self.password = password;
        self
    }

    /// Sets the account display name.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Sets the user's preferred locale, falling back to the default if `None`
    /// is passed.
    pub fn locale(mut self, locale: Option<String>) -> Self {
        self.locale = locale.unwrap_or_else(|| DEFAULT_LOCALE.to_string());
        self
    }

    /// Records the registration or last-access IP address.
    pub fn ip(mut self, ip: Option<String>) -> Self {
        self.ip = ip;
        self
    }

    /// Associates an invitation code with the new user.
    pub fn invite(mut self, invite: Option<String>) -> Self {
        self.invite = invite;
        self
    }
}

/// Helper to construct a `User` from moved parts.
fn construct_user(
    id: Option<UserId>,
    email: Option<EmailAddress>,
    username: String,
    password: PasswordHash,
    locale: String,
    ip: Option<String>,
    invite: Option<String>,
) -> User {
    User {
        id,
        username,
        email,
        password,
        locale,
        ip,
        invite,
        totp_secret: None,
        summary: None,
        avatar: None,
        flags: 0,
        created_at: chrono::Utc::now(),
        deleted_at: None,
        public_keys: Vec::new(),
    }
}

impl UserBuilder<Present<UserId>, Missing> {
    /// Finalizes build using validated ID as the primary identity.
    pub fn build(self) -> User {
        let UserBuilder {
            id: Present(id),
            username,
            email: _,
            password,
            locale,
            ip,
            invite,
        } = self;

        construct_user(Some(id), None, username, password, locale, ip, invite)
    }
}

impl UserBuilder<Missing, Present<EmailAddress>> {
    /// Finalizes build using validated email as the primary identity.
    pub fn build(self) -> User {
        let UserBuilder {
            id: _,
            username,
            email: Present(email),
            password,
            locale,
            ip,
            invite,
        } = self;

        construct_user(
            None,
            Some(email),
            username,
            password,
            locale,
            ip,
            invite,
        )
    }
}

impl UserBuilder<Present<UserId>, Present<EmailAddress>> {
    /// Finalizes build when both a specific ID and a validated email are
    /// provided.
    pub fn build(self) -> User {
        let UserBuilder {
            id: Present(id),
            username,
            email: Present(email),
            password,
            locale,
            ip,
            invite,
        } = self;

        construct_user(
            Some(id),
            Some(email),
            username,
            password,
            locale,
            ip,
            invite,
        )
    }
}
