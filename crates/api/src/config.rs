//! Configuration loading for the server.
//!
//! Reads `config.yaml` and maps it to the adapter/application types.

use std::fs::File;
use std::path::Path;

use application::dto::StatusDto;
use serde::Deserialize;

/// Top-level configuration matching `config.yaml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub url: String,
    pub support: Option<String>,
    pub favicon: Option<String>,
    pub terms_of_service: Option<String>,
    pub privacy_policy: Option<String>,
    #[serde(default)]
    pub invite_only: bool,

    pub postgres: PostgresConfig,
    pub argon2: Argon2Config,
    pub totp: TotpConfig,
    pub token: TokenConfig,
    pub ldap: Option<LdapConfig>,
    pub mail: Option<MailConfig>,
}

impl From<ServerConfig> for StatusDto {
    fn from(config: ServerConfig) -> Self {
        StatusDto {
            name: config.name,
            url: config.url,
            support: config.support,
            favicon: config.favicon,
            background: None,
            terms_of_service: config.terms_of_service,
            privacy_policy: config.privacy_policy,
            invite_only: config.invite_only,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostgresConfig {
    pub address: String,
    pub database: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    #[serde(default)]
    pub tls: bool,
}

fn default_pool_size() -> u32 {
    25
}

#[derive(Debug, Clone, Deserialize)]
pub struct Argon2Config {
    pub memory_cost: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub hash_length: usize,
    pub zxcvbn: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TotpConfig {
    pub issuer: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    pub key_id: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    pub address: String,
    pub base_dn: String,
    pub additional_users_dn: String,
    pub users_filter: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub starttls: Option<bool>,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MailConfig {
    pub address: String,
    pub vhost: Option<String>,
    pub username: String,
    pub password: String,
    pub pool: Option<u16>,
    pub queue: String,
    pub tls: Option<bool>,
}

impl ServerConfig {
    /// Load configuration from a YAML file.
    pub fn load(
        path: impl AsRef<Path>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let config: Self = serde_yaml::from_reader(file)?;
        Ok(config)
    }

    /// Load with default path fallback.
    pub fn load_default() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::var("CONFIG_PATH")
            .unwrap_or_else(|_| "config.yaml".to_string());
        Self::load(&path)
    }

    /// Build the PostgreSQL connection string.
    pub fn postgres_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}/{}",
            self.postgres.username,
            self.postgres.password,
            self.postgres.address,
            self.postgres.database,
        )
    }
}
