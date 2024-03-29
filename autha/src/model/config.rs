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
    /// The connection details for create Kafka instance.
    pub kafka: Option<Connection>,
    /// The connection details for create RabbitMQ instance.
    pub rabbitmq: Option<Connection>,
}

/// Supported platforms for image hosting.
#[derive(Deserialize, Debug, Clone)]
pub enum Platforms {
    Cloudinary,
}

/// Represents the SaaS.
#[derive(Deserialize, Debug, Clone)]
pub struct Image {
    /// The platform selected to host images.
    pub platform: Platforms,
    /// The platform's API key.
    pub key: String,
    /// For Cloudinary, the cloud name.
    pub cloud_name: Option<String>,
    /// The platform's API secret.
    pub secret: String,
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
    /// SaaS to host, modify and save images.
    pub image_delivery: Option<Image>,
    /// Wether to start /metric endpoint.
    pub prometheus: Option<bool>,
    /// Jaeger traces in OpenTelemetry OTLP format URL (should be port 4317).
    pub jaeger_url: Option<String>,
}

/// Represents non-private informations transmitted on login to make
/// a global ecosystem on Gravitalia.
#[derive(Serialize)]
pub struct UserSettings {
    /// ISO 639-1 language code.
    pub locale: String,
}
