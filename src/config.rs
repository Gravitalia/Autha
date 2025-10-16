//! Configuration manager for Autha.

use axum::extract::FromRef;
use serde::{Deserialize, Serialize};
use url::Url;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::AppState;

const DEFAULT_CONFIG_PATH: &str = "config.yaml";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Configuration {
    /// Instance name.
    pub name: String,
    /// Domain name of current instance.
    pub url: String,
    favicon: Option<String>,
    background: Option<String>,
    terms_of_service: Option<String>,
    privacy_policy: Option<String>,
    /// whether user registration requires an invite code.
    pub invite_only: bool,
    #[serde(skip_deserializing)]
    version: String,
    #[serde(skip)]
    path: PathBuf,
    /// Related to JsonWebToken configuration.
    #[serde(skip_serializing)]
    pub token: Token,
    /// Related to PostgreSQL configuration.
    #[serde(skip_serializing)]
    pub postgres: Option<Postgres>,
    /// Related to LDAP3 configuration.
    #[serde(skip_serializing)]
    pub ldap: Option<Ldap>,
    /// Related to MFA via TOTP configuration.
    #[serde(skip_serializing)]
    pub totp: Option<Totp>,
}

/// PostgreSQL configuration.
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct Postgres {
    /// Hostname:(?port) for PostgreSQL instance.
    pub address: String,
    /// Database name.
    pub database: Option<String>,
    /// Username credential to connect.
    pub username: Option<String>,
    /// Password credential to connect.
    pub password: Option<String>,
    ssl: bool,
}

/// PostgreSQL configuration.
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct Token {
    pub public_key_pem: String,
    pub private_key_pem: String,
}

/// LDAP configuration.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ldap {
    /// Hostname:(?port) for LDAP instance.
    pub address: String,
    /// Admin DN credential to connect.
    pub user: Option<String>,
    /// Password credential to connect.
    pub password: Option<String>,
    /// DN for domain.
    pub base_dn: Option<String>,
    /// Useful for organization unit (OU).
    pub additional_users_dn: Option<String>,
    pub users_filter: Option<String>,
    /// Useful for organization unit (OU).
    pub additional_groups_dn: Option<String>,
    pub groups_filter: Option<String>,
}

/// TOTP configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Totp {
    algorithm: String,
    /// Number of digits for the code.
    pub digits: u16,
    /// Window for code usage.
    pub period: usize,
}

impl Default for Totp {
    fn default() -> Self {
        Self {
            algorithm: "sha1".into(),
            digits: 6,
            period: 30,
        }
    }
}

impl FromRef<AppState> for Arc<Configuration> {
    fn from_ref(state: &AppState) -> Arc<Configuration> {
        Arc::clone(&state.config)
    }
}

impl Configuration {
    pub fn path(mut self, path: PathBuf) -> Self {
        self.path = path;
        self
    }

    /// Normalizes a URL string by ensuring it starts with a valid scheme (`http` or `https`).
    fn normalize_url(&self, url: &str) -> Result<String, url::ParseError> {
        let url_with_scheme = if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("https://{url}")
        };

        let parsed_url = Url::parse(&url_with_scheme)?;
        Ok(parsed_url.to_string())
    }

    /// Reads the `config.yaml` file from the specified path or the default location.
    pub fn read(self) -> Result<Arc<Self>, url::ParseError> {
        let file_path = if self.path.is_file() {
            &self.path
        } else {
            &Path::new(DEFAULT_CONFIG_PATH).to_path_buf()
        };

        match File::open(file_path) {
            Ok(file) => {
                let mut config: Configuration = match serde_yaml::from_reader(file) {
                    Ok(config) => config,
                    Err(err) => {
                        return Ok(Arc::new(self.error(err)));
                    }
                };

                // set app version.
                config.version = VERSION.to_owned();

                // normalize URLs.
                config.url = self.normalize_url(&config.url)?;
                config.favicon = config.favicon.map(|f| self.normalize_url(&f)).transpose()?;
                config.terms_of_service = config
                    .terms_of_service
                    .map(|f| self.normalize_url(&f))
                    .transpose()?;
                config.privacy_policy = config
                    .privacy_policy
                    .map(|f| self.normalize_url(&f))
                    .transpose()?;
                config.background = config
                    .background
                    .map(|b| self.normalize_url(&b))
                    .transpose()?;

                Ok(Arc::new(config))
            }
            Err(err) => Ok(Arc::new(self.error(err))),
        }
    }

    /// Return a default configuration as fallback.
    fn error(&self, err: impl std::error::Error) -> Self {
        tracing::error!(error = %err, "`config.yaml` file not found");
        Self {
            version: VERSION.to_owned(),
            ..Default::default()
        }
    }
}
