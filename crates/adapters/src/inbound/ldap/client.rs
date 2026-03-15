//! LDAP client implementation.

use std::collections::HashSet;

use application::error::{ApplicationError, Result, ToInternal};
use application::ports::outbound::{LdapPort, LdapUserAttributes};
use async_trait::async_trait;
use ldap3::{
    Ldap as Ldap3Connection, LdapConnAsync, LdapConnSettings, Scope,
    SearchEntry,
};

use crate::inbound::ldap::config::{LdapConfig, escape_ldap_value};

/// LDAP client adapter.
pub struct LdapClient {
    config: LdapConfig,
}

impl LdapClient {
    /// Create a new [`LdapClient`].
    pub fn new(config: LdapConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Create a new LDAP connection.
    async fn create_connection(&self) -> Result<Ldap3Connection> {
        let settings =
            LdapConnSettings::new().set_starttls(self.config.start_tls);

        let (conn, ldap) =
            LdapConnAsync::with_settings(settings, &self.config.address)
                .await
                .catch()?;

        ldap3::drive!(conn);

        Ok(ldap)
    }

    /// Create an authenticated LDAP connection (bind as admin).
    async fn create_admin_connection(&self) -> Result<Ldap3Connection> {
        let mut ldap = self.create_connection().await?;

        if let Some(bind_dn) = &self.config.bind_dn {
            let bind_password = self
                .config
                .bind_password
                .as_ref()
                .ok_or_else(|| ApplicationError::Unknown)?;

            ldap.simple_bind(bind_dn, bind_password)
                .await
                .catch()?
                .success()
                .catch()?;
        }

        Ok(ldap)
    }

    /// Search for a user by username.
    async fn find_user_dn(&self, username: &str) -> Result<Option<String>> {
        let mut ldap = self.create_admin_connection().await?;

        let filter = self.config.user_search_filter(username);
        let base_dn = self.config.build_users_base_dn();

        let (results, _) = ldap
            .search(&base_dn, Scope::Subtree, &filter, vec!["dn"])
            .await
            .catch()?
            .success()
            .catch()?;

        if results.is_empty() {
            return Ok(None);
        }

        if results.len() > 1 {
            tracing::warn!(
                username = username,
                count = results.len(),
                "multiple ldap entries found for username"
            );
            return Err(ApplicationError::Unknown);
        }

        let entry = SearchEntry::construct(results[0].clone());
        Ok(Some(entry.dn))
    }
}

#[async_trait]
impl LdapPort for LdapClient {
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<()> {
        if password.is_empty() {
            return Err(ApplicationError::Unknown);
        }

        let user_dn = self
            .find_user_dn(username)
            .await?
            .ok_or_else(|| ApplicationError::Unknown)?;

        let mut ldap = self.create_connection().await?;

        ldap.simple_bind(&user_dn, password)
            .await
            .catch()?
            .success()
            .catch()?;

        // Unbind to clean up.
        let _ = ldap.unbind().await;

        Ok(())
    }

    async fn add_user(
        &self,
        user_id: &str,
        attributes: &LdapUserAttributes,
    ) -> Result<()> {
        let mut ldap = self.create_admin_connection().await?;

        let escaped_user_id = escape_ldap_value(user_id);
        let dn = self.config.build_user_dn(&escaped_user_id);

        let mut attrs = vec![
            (
                "objectClass",
                HashSet::from([
                    "top",
                    "person",
                    "organizationalPerson",
                    "inetOrgPerson",
                ]),
            ),
            ("uid", HashSet::from([escaped_user_id.as_str()])),
            ("cn", HashSet::from([attributes.username.as_str()])),
            ("sn", HashSet::from([attributes.username.as_str()])),
        ];

        if let Some(email) = &attributes.email {
            attrs.push(("mail", HashSet::from([email.as_str()])));
        }

        if let Some(display_name) = &attributes.display_name {
            attrs
                .push(("displayName", HashSet::from([display_name.as_str()])));
        }

        ldap.add(&dn, attrs).await.catch()?.success().catch()?;

        let _ = ldap.unbind().await;

        tracing::info!(user_id = user_id, "user added to ldap");

        Ok(())
    }
}
