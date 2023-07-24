use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub services: Vec<String>,
}
