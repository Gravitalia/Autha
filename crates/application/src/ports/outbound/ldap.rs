//! Interface for LDAP operations.

use async_trait::async_trait;

use crate::error::Result;

/// Port for LDAP authentication and user management.
#[async_trait]
pub trait LdapPort: Send + Sync {
    /// Authenticate a user against LDAP credentials.
    async fn authenticate(&self, username: &str, password: &str)
    -> Result<()>;

    /// Add a new user to LDAP.
    async fn add_user(
        &self,
        user_id: &str,
        attributes: &LdapUserAttributes,
    ) -> Result<()>;
}

/// Attributes for LDAP user creation.
#[derive(Debug, Clone, Default)]
pub struct LdapUserAttributes {
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}
