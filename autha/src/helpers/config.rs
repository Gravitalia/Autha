use crate::model::config::Config;
use std::fs::File;

/// The name of the configuration file.
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
///
/// # Returns
///
/// The parsed `Config` struct representing the configuration from the file.
pub fn read() -> Config {
    let config: Config =
        serde_yaml::from_reader(File::open(FILE_NAME).expect("Failed to open config.yaml file"))
            .expect("Failed to deserialize config.yaml contents");

    config
}
