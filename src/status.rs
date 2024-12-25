//! Configuration reader.

use serde::Deserialize;
use tracing::error;

use std::fs::File;
use std::path::{Path, PathBuf};

const DEFAULT_STATUS_PATH: &str = "status.json";

/// Structure of  `status.json` file.
#[derive(Deserialize, Default, Debug)]
pub struct Configuration {
    name: String,
    url: String,
    favicon: Option<String>,
    terms_of_service: String,
    privacy_policy: String,
    version: u8,
    invite_only: bool,
    background: Option<String>,
}

impl Configuration {
    /// Read ``status.json` file.
    pub fn read(path: Option<PathBuf>) -> Self {
        match File::open(path.unwrap_or(Path::new(&DEFAULT_STATUS_PATH).to_path_buf())) {
            Ok(file) => match serde_json::from_reader(file) {
                Ok(config) => config,
                Err(err) => {
                    error!(error = %err, "`status.json` haven't been deserialized");

                    Self {
                        version: 1,
                        ..Default::default()
                    }
                }
            },
            Err(err) => {
                error!(error = %err, "`status.json` file cannot be found");

                Self {
                    version: 1,
                    ..Default::default()
                }
            }
        }
    }
}
