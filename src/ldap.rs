//! LDAP support.

use ldap3::{Ldap as Ldap3, LdapConnAsync, LdapError, Scope, SearchEntry};

use crate::user::User;

/// LDAP manager to create connection.
#[derive(Clone, Debug, Default)]
pub struct Ldap {
    conn: Option<Ldap3>,
    addr: String,
    template: String,
    path: String,
}

impl Ldap {
    /// Create a new [`Ldap3`] connection.
    pub async fn new<T: ToString>(
        addr: T,
        dn: Option<String>,
        password: Option<String>,
    ) -> Result<Self, LdapError> {
        let addr = addr.to_string();
        let (conn, mut ldap) = LdapConnAsync::new(&addr).await?;
        ldap3::drive!(conn);

        if let Some(dn) = dn {
            ldap.simple_bind(&dn, &password.unwrap_or_default())
                .await?
                .success()?;
        }

        tracing::info!(%addr, "LDAP connected");

        Ok(Ldap {
            conn: Some(ldap),
            addr,
            template: "ou=People, dc=gravitalia, dc=com, uid={user_id}, cn={username}".to_owned(),
            path: "ou=People, dc=gravitalia, dc=com".to_owned(),
        })
    }

    /// Update `dn` entry for LDAP requests.
    pub async fn with_template(mut self, template: &str) -> Self {
        use regex_lite::Regex;

        self.template = template.to_owned();
        self.path = if let Ok(re) = Regex::new(r"[ ,]*(uid|cn)=[^,]+") {
            re.replace_all(template, "").to_string()
        } else {
            String::default()
        };

        self
    }

    /// Create a new entry on [`Ldap3`].
    pub async fn add(mut self, user: User) -> Result<(), LdapError> {
        let Some(ref mut conn) = self.conn else {
            return Err(LdapError::EmptyUnixPath);
        };

        if self.template.is_empty() {
            tracing::warn!("LDAP `dn` template is empty; not saving new entries");
            return Ok(());
        }

        tracing::info!(user_id = user.id, "add new entry on LDAP");

        let dn = self
            .template
            .replace("{user_id}", &user.id)
            .replace("{username}", &user.username);
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
            ("mail", [user.email.as_str()].into_iter().collect()),
            (
                "userPassword",
                [user.password.as_str()].into_iter().collect(),
            ),
        ];

        conn.add(&dn, attrs).await?;
        Ok(())
    }

    /// Test a connection on [`Ldap3`].
    /// Do not re-use this connection after.
    pub async fn bind(&self, user: &User, password: &str) -> Result<(), LdapError> {
        let (conn_handle, mut conn) = LdapConnAsync::new(&self.addr).await?;
        ldap3::drive!(conn_handle);

        tracing::debug!(user_id = %user.id, "Trying to bind user...");

        let search = conn
            .search(
                &self.path,
                Scope::Subtree,
                &format!("(uid={})", user.id),
                vec!["dn"],
            )
            .await?
            .success()?
            .0;

        let dn = SearchEntry::construct(search[0].clone()).dn;

        conn.simple_bind(&dn, password).await?.success()?;
        conn.unbind().await?;
        Ok(())
    }
}
