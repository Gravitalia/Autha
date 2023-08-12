use serde::Deserialize;

/// Config represents how config.yaml should be
#[derive(Deserialize, Debug)]
pub struct Config {
    pub services: Vec<String>,
}
