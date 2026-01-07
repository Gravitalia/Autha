//! Typed builder for User.

use std::sync::Arc;

use sqlx::{Pool, Postgres};

use crate::crypto::Crypto;
use crate::user::{User, UserService};

const DEFAULT_LOCALE: &str = "en";

/// [`User`] builder.
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

/// Value is missing on [`UserBuilder`].
#[derive(Debug, Clone)]
pub struct Missing;

/// Value is present on [`UserBuilder`].
#[derive(Debug, Clone)]
pub struct Present<T>(pub T);

impl UserBuilder<Missing, Missing> {
    /// Create a new [`UserBuilder`].
    pub fn new() -> Self {
        Self {
            id: Missing,
            username: String::default(),
            email: Missing,
            password: String::default(),
            locale: DEFAULT_LOCALE.to_string(),
            ip: None,
            invite: None,
        }
    }
}

impl<Email> UserBuilder<Missing, Email> {
    /// Update `id` field on [`UserBuilder`].
    pub fn id(
        self,
        id: impl Into<String>,
    ) -> UserBuilder<Present<String>, Email> {
        UserBuilder {
            id: Present(id.into().to_lowercase()),
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
    /// Update `email` field on [`UserBuilder`].
    pub fn email(
        self,
        email: impl Into<String>,
    ) -> UserBuilder<Id, Present<String>> {
        UserBuilder {
            id: self.id,
            username: self.username,
            email: Present(email.into()),
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
        }
    }
}

impl<Id, Email> UserBuilder<Id, Email> {
    /// Update `password` field on [`UserBuilder`].
    pub fn password(mut self, password: impl ToString) -> Self {
        self.password = password.to_string();
        self
    }

    /// Update `username` field on [`UserBuilder`].
    pub fn username(mut self, username: impl ToString) -> Self {
        self.username = username.to_string();
        self
    }

    /// Update `locale` field on [`UserBuilder`].
    pub fn locale(mut self, locale: Option<String>) -> Self {
        self.locale = locale.unwrap_or(DEFAULT_LOCALE.to_string());
        self
    }

    /// Update `ip` field on [`UserBuilder`].
    pub fn ip(mut self, ip: Option<String>) -> Self {
        self.ip = ip;
        self
    }

    /// Update `invite` field on [`UserBuilder`].
    pub fn invite(mut self, invite: Option<String>) -> Self {
        self.invite = invite;
        self
    }
}

impl UserBuilder<Missing, Present<String>> {
    /// Build a [`User`] with `email`.
    pub fn build(
        self,
        pool: Pool<Postgres>,
        crypto: Arc<Crypto>,
    ) -> UserService {
        let user = User {
            id: String::default(),
            username: self.username,
            email_hash: self.email.0.clone(),
            email_cipher: self.email.0,
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
            ..Default::default()
        };

        crate::user::service::UserService::new(user, pool, crypto)
    }
}

impl UserBuilder<Present<String>, Missing> {
    /// Build a [`User`] with `id`.
    pub fn build(
        self,
        pool: Pool<Postgres>,
        crypto: Arc<Crypto>,
    ) -> UserService {
        let user = User {
            id: self.id.0,
            username: self.username,
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
            ..Default::default()
        };

        crate::user::service::UserService::new(user, pool, crypto)
    }
}

impl UserBuilder<Present<String>, Present<String>> {
    /// Build a [`User`] with `id` and `email`.
    pub fn build(
        self,
        pool: Pool<Postgres>,
        crypto: Arc<Crypto>,
    ) -> UserService {
        let user = User {
            id: self.id.0,
            username: self.username,
            email_hash: self.email.0.clone(),
            email_cipher: self.email.0,
            password: self.password,
            locale: self.locale,
            ip: self.ip,
            invite: self.invite,
            ..Default::default()
        };

        crate::user::service::UserService::new(user, pool, crypto)
    }
}
