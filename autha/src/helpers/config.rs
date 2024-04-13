use crate::model::config::Config;
use std::fs::File;

const FILE_NAME: &str = "config.yaml";

/// Reads the configuration file and returns the parsed configuration.
///
/// This function opens the configuration file named `config.yaml` and attempts
/// to deserialize its contents into a `Config` struct. If the file cannot be found
/// or its contents cannot be properly deserialized, the function will panic.
///
/// # Panics
///
/// This function may panic if the `config.yaml` file cannot be found or if its
/// contents cannot be deserialized into a `Config` struct.
pub fn read() -> Config {
    let config: Config = serde_yaml::from_reader(
        File::open(
            std::env::var("CONFIG_PATH").unwrap_or(FILE_NAME.to_string()),
        )
        .expect("Failed to open config.yaml file"),
    )
    .expect("Failed to deserialize config.yaml contents");

    config
}
