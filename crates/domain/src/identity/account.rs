//! Typed builder for `User`.

use crate::identity::email::EmailAddress;
use crate::identity::id::UserId;
use crate::identity::user::User;

const DEFAULT_LOCALE: &str = "en";

/// Marker interface of missing value.
#[derive(Debug, Clone)]
pub struct Missing;

/// Marker interface of present value.
#[derive(Debug, Clone)]
pub struct Present<T>(pub T);

/// A builder to track presence of `Id` and `Email`.
#[derive(Debug, Clone)]
pub struct UserBuilder<Id, Email> {
    id: Id,
    username: String,
    email: Email,
    password: String,
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
            password: String::new(),
            locale: DEFAULT_LOCALE.to_string(),
            ip: None,
            invite: None,
        }
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
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
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

impl UserBuilder<Present<String>, Missing> {
    /// Finalizes the build when only a manual ID string is provided.
    pub fn build(self) -> User {
        User {
            id: self.id.0,
            username: self.username,
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
            ..Default::default()
        }
    }
}

impl UserBuilder<Missing, Present<EmailAddress>> {
    /// Finalizes the build using the validated email as the primary identity.
    ///
    /// Note: The raw email string is used to populate internal hash and cipher
    /// fields.
    pub fn build(self) -> User {
        let email_str = self.email.0.as_str().to_string();
        User {
            id: String::new(),
            username: self.username,
            email_hash: email_str.clone(),
            email_cipher: email_str,
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
            ..Default::default()
        }
    }
}

impl UserBuilder<Present<String>, Present<EmailAddress>> {
    /// Finalizes build when both a specific ID and a validated email are
    /// provided.
    pub fn build(self) -> User {
        let email_str = self.email.0.as_str().to_string();
        User {
            id: self.id.0,
            username: self.username,
            email_hash: email_str.clone(),
            email_cipher: email_str,
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
            ..Default::default()
        }
    }
}
