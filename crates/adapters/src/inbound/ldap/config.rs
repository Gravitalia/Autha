//! LDAP configuration.

use application::error::{ApplicationError, Result};
use zeroize::Zeroizing;

/// LDAP connection configuration.
#[derive(Clone)]
pub struct LdapConfig {
    pub address: String,
    pub base_dn: String,
    /// DN template for users (e.g., "uid={uid},ou=users,dc=example,dc=com").
    /// Use `{uid}` as placeholder for the username.
    pub user_dn_template: String,
    /// Additional DN for users (organizational unit).
    pub additional_users_dn: String,
    pub users_filter: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<Zeroizing<String>>,
    pub start_tls: bool,
    pub ca_certificate: Option<String>,
}

impl LdapConfig {
    /// Create a new [`LdapConfig`].
    pub fn new(
        address: impl Into<String>,
        base_dn: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            base_dn: base_dn.into(),
            user_dn_template: "uid={uid},ou=users,{base_dn}".to_string(),
            additional_users_dn: "ou=users".to_string(),
            users_filter: None,
            bind_dn: None,
            bind_password: None,
            start_tls: false,
            ca_certificate: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.user_dn_template.contains("{uid}") {
            return Err(ApplicationError::Unknown);
        }

        if self.bind_dn.is_some() && self.bind_password.is_none() {
            return Err(ApplicationError::Unknown);
        }

        Ok(())
    }

    /// Build the full DN for a user.
    pub fn build_user_dn(&self, uid: &str) -> String {
        self.user_dn_template
            .replace("{uid}", &escape_ldap_value(uid))
            .replace("{base_dn}", &self.base_dn)
    }

    /// Build the full DN for the users container.
    pub fn build_users_base_dn(&self) -> String {
        format!("{},{}", self.additional_users_dn, self.base_dn)
    }

    /// Get the user search filter.
    pub fn user_search_filter(&self, uid: &str) -> String {
        self.users_filter
            .clone()
            .unwrap_or_else(|| format!("(uid={})", escape_ldap_value(uid)))
    }
}

/// Escape special LDAP characters in values (RFC 4514).
pub fn escape_ldap_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);

    for ch in input.chars() {
        match ch {
            '*' => out.push_str(r"\2a"),
            '(' => out.push_str(r"\28"),
            ')' => out.push_str(r"\29"),
            '\\' => out.push_str(r"\5c"),
            '\0' => out.push_str(r"\00"),
            ',' => out.push_str(r"\2c"),
            '+' => out.push_str(r"\2b"),
            '"' => out.push_str(r"\22"),
            '<' => out.push_str(r"\3c"),
            '>' => out.push_str(r"\3e"),
            ';' => out.push_str(r"\3b"),
            '=' => out.push_str(r"\3d"),
            _ => out.push(ch),
        }
    }

    out
}
