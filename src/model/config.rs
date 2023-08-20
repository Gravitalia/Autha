use serde::Deserialize;

/// Connection represents database informations to connect
#[derive(Deserialize, Debug, Clone)]
pub struct Connection {
    pub username: Option<String>,
    pub password: Option<String>,
    pub hosts: Vec<String>
}

/// Nats represents NATS required informations
#[derive(Deserialize, Debug, Clone)]
pub struct Nats {
    pub publish: bool,
    pub host: String
}

/// Database represents the databases connection datas
#[derive(Deserialize, Debug, Clone)]
pub struct Database {
    pub scylla: Connection,
    pub memcached: Connection,
    pub nats: Nats,
}

/// Config represents how config.yaml should be
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub database: Database,
    pub services: Vec<String>,
}
