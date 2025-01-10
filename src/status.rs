//! Configuration reader.

use serde::{Deserialize, Serialize};
use tracing::error;
use url::Url;

use std::fs::File;
use std::path::{Path, PathBuf};

const DEFAULT_STATUS_PATH: &str = "status.json";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors that may occur during the configuration loading process.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("URL is invalid: {0}")]
    Url(#[from] url::ParseError),
    #[error("Failed to deserialize `status.json`: {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Structure of the `status.json` file.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Configuration {
    name: String,
    url: String,
    favicon: Option<String>,
    terms_of_service: String,
    privacy_policy: String,
    #[serde(skip_deserializing)]
    version: String,
    invite_only: bool,
    background: Option<String>,
}

impl 

<crate::AppState> for Configuration {
    fn from_ref(app_state: &crate::AppState) -> Configuration {
        app_state.config.clone()
    }
}

impl Configuration {
    /// Reads the `status.json` file from the specified path or the default location.
    pub fn read(path: Option<PathBuf>) -> Result<Self, Error> {
        let file_path = path.unwrap_or_else(|| Path::new(DEFAULT_STATUS_PATH).to_path_buf());

        match File::open(&file_path) {
            Ok(file) => {
                let mut config: Configuration = serde_json::from_reader(file)?;

                // set app version.
                config.version = VERSION.to_owned();

                // normalize URLs.
                config.url = normalize_url(&config.url)?;
                config.favicon = config.favicon.map(|f| normalize_url(&f)).transpose()?;
                config.terms_of_service = normalize_url(&config.terms_of_service)?;
                config.privacy_policy = normalize_url(&config.privacy_policy)?;
                config.background = config.background.map(|b| normalize_url(&b)).transpose()?;

                Ok(config)
            }
            Err(err) => {
                error!(error = %err, "`status.json` file cannot be found");

                // return a default configuration as fallback.
                Ok(Self {
                    version: VERSION.to_owned(),
                    ..Default::default()
                })
            }
        }
    }
}

/// Normalizes a URL string by ensuring it starts with a valid scheme (`http` or `https`).
fn normalize_url(url: &str) -> Result<String, Error> {
    let url_with_scheme = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };

    let parsed_url = Url::parse(&url_with_scheme)?;
    Ok(parsed_url.to_string())
}
