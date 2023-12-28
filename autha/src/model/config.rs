use serde::{Deserialize, Serialize};

/// Represents the connection information required to connect to a database.
#[derive(Deserialize, Debug, Clone)]
pub struct Connection {
    /// The optional username for authentication.
    pub username: Option<String>,
    /// The optional password for authentication.
    pub password: Option<String>,
    /// A list of host addresses for the database connection.
    pub hosts: Vec<String>,
    /// Number of pool created for database.
    pub pool_size: u32,
}

/// Represents the connection details for the databases.
#[derive(Deserialize, Debug, Clone)]
pub struct Database {
    /// The connection details for memcached.
    pub memcached: Connection,
    /// The connection details for ScyllaDB or Apache Cassandra.
    pub scylla: Connection,
}

/// Represents the configuration structure expected from the 'config.yaml' file.
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// The port number for the server.
    pub port: u16,
    /// If set, check that the new avatars do not contain any nudity.
    /// Otherwise, skip the verification stage and authorise all avatars.
    /// This can be useful for reducing latency and bandwidth consumption.
    pub(crate) remini_url: Option<String>,
    /// The database configuration.
    pub database: Database,
}

/// Represents non-private informations transmitted on login to make
/// a global ecosystem on Gravitalia.
#[derive(Serialize)]
pub struct UserSettings {
    /// ISO 639-1 language code.
    pub locale: String,
}
