use crate::model::config::Config;

// Define constant variable for the name of the file
const FILE_NAME: &str = "config.yaml";

// Read configuration file, and then, returns it
pub fn read() -> Config {
    let config: Config = serde_yaml::from_reader(
        std::fs::File::open(FILE_NAME)
            .expect("Could not find config.yaml file"),
    )
    .expect("Could not read values of config.yaml file");

    config
}
