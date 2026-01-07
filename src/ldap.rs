//! LDAP support.

use ldap3::{Ldap as Ldap3, LdapConnAsync, LdapError, Scope, SearchEntry};

use crate::crypto::SymmetricCipher;
use crate::error::Result;
use crate::user::User;

#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub addr: String,
    pub base_dn: String,
    pub user_dn_template: String,
}

impl LdapConfig {
    /// Create a new [`LdapConfig`].
    pub fn new(
        addr: impl Into<String>,
        base_dn: impl Into<String>,
        user_dn_template: impl Into<String>,
    ) -> Result<Self> {
        let template = user_dn_template.into();

        if !template.contains("{uid}") {
            return Err(LdapError::FilterParsing.into());
        }

        Ok(Self {
            addr: addr.into(),
            base_dn: base_dn.into(),
            user_dn_template: template,
        })
    }

    /// Configure LDAP `dn` for user identifier.
    pub fn user_dn(&self, uid: &str) -> String {
        self.user_dn_template.replace("{uid}", &escape_ldap(uid))
    }
}

/// LDAP manager to create connection.
#[derive(Clone, Debug)]
pub struct Ldap {
    conn: Ldap3,
    config: LdapConfig,
}

impl Ldap {
    /// Create a new [`Ldap3`] connection.
    pub async fn connect(
        config: LdapConfig,
        bind_dn: Option<&str>,
        bind_password: Option<&str>,
    ) -> Result<Self> {
        let (handle, mut conn) = LdapConnAsync::new(&config.addr).await?;
        ldap3::drive!(handle);

        if let Some(dn) = bind_dn {
            let password = bind_password.ok_or_else(|| {
                LdapError::InvalidScopeString("password".into())
            })?;

            conn.simple_bind(dn, password).await?.success()?;
        }

        Ok(Self { conn, config })
    }

    /// Create a new entry on [`Ldap3`].
    pub async fn add_user(
        &mut self,
        crypto: &SymmetricCipher,
        user: &User,
    ) -> Result<()> {
        let dn = self.config.user_dn(&user.id);
        let email = crypto.decrypt_from_hex(&user.email_cipher)?;

        let attrs = vec![
            (
                "objectClass",
                [
                    "top",
                    "person",
                    "organizationalPerson",
                    "inetOrgPerson",
                    "posixAccount",
                    "shadowAccount",
                ]
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            ),
            ("uid", [user.id.as_str()].into_iter().collect()),
            ("cn", [user.username.as_str()].into_iter().collect()),
            ("mail", [email.as_str()].into_iter().collect()),
            (
                "userPassword",
                [user.password.as_str()].into_iter().collect(),
            ),
        ];

        self.conn.add(&dn, attrs).await?.success()?;
        Ok(())
    }

    /// Test a connection on [`Ldap3`].
    ///
    /// SAFETY: Do not use connection after.
    pub async fn authenticate(&self, uid: &str, password: &str) -> Result<()> {
        let (handle, mut conn) = LdapConnAsync::new(&self.config.addr).await?;
        ldap3::drive!(handle);

        let filter = format!("(uid={})", escape_ldap(uid));
        let results = conn
            .search(&self.config.base_dn, Scope::Subtree, &filter, vec!["dn"])
            .await?
            .success()?
            .0;

        if results.len() != 1 {
            return Err(crate::error::ServerError::Unauthorized);
        }

        let dn = SearchEntry::construct(results[0].clone()).dn;
        conn.simple_bind(&dn, password).await?.success()?;
        conn.unbind().await?;
        Ok(())
    }
}

fn escape_ldap(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match *b {
            b'*' => out.push_str(r"\2a"),
            b'(' => out.push_str(r"\28"),
            b')' => out.push_str(r"\29"),
            b'\\' => out.push_str(r"\5c"),
            0 => out.push_str(r"\00"),
            c => out.push(c as char),
        }
    }
    out
}
