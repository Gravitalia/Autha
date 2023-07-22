use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub services: Vec<String>
}

pub fn read() -> Config {
    let config: Config = serde_yaml::from_reader(std::fs::File::open("config.yaml").expect("Could not find config.yaml file")).expect("Could not read values of config.yaml file");

    println!("Configuration read-out complete");

    config
}