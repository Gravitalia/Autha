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
    pub async fn new(
        addr: &str,
        dn: Option<String>,
        password: Option<String>,
    ) -> Result<Self, LdapError> {
        let (conn, mut ldap) = LdapConnAsync::new(addr).await?;
        ldap3::drive!(conn);

        if let Some(dn) = dn {
            ldap.simple_bind(&dn, &password.unwrap_or_default())
                .await?
                .success()?;
        }

        tracing::info!(%addr, "ldap connected");

        Ok(Ldap {
            conn: Some(ldap),
            addr: addr.to_owned(),
            template:
                "ou=People, dc=gravitalia, dc=com, uid={user_id}, cn={username}"
                    .to_owned(),
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
    pub async fn add(mut self, user: &User) -> Result<(), LdapError> {
        let Some(ref mut conn) = self.conn else {
            tracing::debug!(?self.conn, user_id = user.id, "user add on ldap failed");
            return Ok(());
        };

        if self.template.is_empty() {
            tracing::warn!(
                "LDAP `dn` template is empty; not saving new entries"
            );
            return Ok(());
        }

        tracing::info!(user_id = user.id, "add new entry on ldap");

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
    pub async fn bind(
        &self,
        user_id: &str,
        password: &str,
    ) -> Result<(), LdapError> {
        let (conn_handle, mut conn) = LdapConnAsync::new(&self.addr).await?;
        ldap3::drive!(conn_handle);

        tracing::debug!(%user_id, "binding ldap user");

        let user_id = escape_ldap(user_id);
        let search = conn
            .search(
                &self.path,
                Scope::Subtree,
                &format!("(uid={user_id})"),
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
