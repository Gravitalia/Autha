use serde::Deserialize;

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
    /// The connection details for Neo4j or Memgraph.
    pub bolt: Connection,
}

/// Represents the configuration structure expected from the 'config.yaml' file.
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// The port number for the server.
    pub port: u16,
    /// The database configuration.
    pub database: Database,
}
