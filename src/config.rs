//! Configuration manager for Autha.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::FromRef;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::AppState;

const DEFAULT_CONFIG_PATH: &str = "config.yaml";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Configuration {
    /// Instance name.
    pub name: String,
    /// Domain name of current instance.
    pub url: String,
    support: Option<String>,
    favicon: Option<String>,
    background: Option<String>,
    terms_of_service: Option<String>,
    privacy_policy: Option<String>,
    /// whether user registration requires an invite code.
    pub invite_only: bool,
    #[serde(default)]
    version: String,
    #[serde(skip)]
    path: PathBuf,
    /// Related to JsonWebToken configuration.
    #[serde(skip_serializing)]
    pub token: Option<Token>,
    /// Related to PostgreSQL configuration.
    #[serde(skip_serializing)]
    pub postgres: Option<Postgres>,
    /// Related to Argon2 configuration.
    #[serde(skip_serializing)]
    pub argon2: Option<Argon2>,
    /// Related to automatic mail sending.
    #[serde(skip_serializing)]
    pub mail: Option<Mail>,
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
    /// Maximum pool connections.
    pub pool_size: Option<u32>,
    tls: bool,
}

/// Argon2 configuration.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Argon2 {
    /// Memory used while hashing.
    pub memory_cost: u32,
    /// Iterations of hash.
    pub iterations: u32,
    /// Parallelism degree.
    pub parallelism: u32,
    /// Output hash length.
    pub hash_length: usize,
    /// Dropbox password strenght measurment.
    pub zxcvbn: Option<u8>,
}

impl Default for Argon2 {
    fn default() -> Self {
        Self {
            memory_cost: 1024 * 64, // 64 MiB.
            iterations: 4,
            parallelism: 2,
            hash_length: 32,
            zxcvbn: Some(2),
        }
    }
}

/// Gravitalia Maily configuration.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mail {
    /// Hostname:(?port) for RabbitMQ instance.
    pub address: String,
    /// RabbitMQ default vhost.
    pub vhost: Option<String>,
    /// RabbitMQ username to access queue.
    pub username: String,
    /// RabbitMQ password to access queue.
    pub password: String,
    /// Max channel connections.
    pub pool: Option<u16>,
    /// Queue name to send mailing events.
    pub queue: String,
    /// Encryption layer.
    pub tls: Option<bool>,
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
    pub base_dn: String,
    /// Useful for organization unit (OU).
    pub additional_users_dn: String,
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

/// Json Web Token configuration.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Token {
    pub key_id: Option<String>,
    pub public_key_pem: String,
    pub private_key_pem: String,
    /// Update token audience.
    /// Default is `account.gravitalia.com`.
    pub audience: Option<String>,
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

    /// Normalizes a URL string by ensuring it starts with a valid scheme
    /// (`http` or `https`).
    fn normalize_url(&self, url: &str) -> Result<String, url::ParseError> {
        let url_with_scheme =
            if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("https://{url}")
            };

        let parsed_url = Url::parse(&url_with_scheme)?;
        Ok(parsed_url.to_string())
    }

    /// Reads the `config.yaml` file from the specified path or the default
    /// location.
    pub fn read(self) -> Result<Arc<Self>, url::ParseError> {
        let file_path = if self.path.is_file() {
            &self.path
        } else {
            &Path::new(DEFAULT_CONFIG_PATH).to_path_buf()
        };

        match File::open(file_path) {
            Ok(file) => {
                let mut config: Configuration =
                    match serde_yaml::from_reader(file) {
                        Ok(config) => config,
                        Err(err) => {
                            return Ok(Arc::new(self.error(err)));
                        },
                    };

                // set app version.
                config.version = VERSION.to_owned();

                // normalize URLs.
                config.url = self.normalize_url(&config.url)?;
                config.favicon = config
                    .favicon
                    .map(|f| self.normalize_url(&f))
                    .transpose()?;
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
            },
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
