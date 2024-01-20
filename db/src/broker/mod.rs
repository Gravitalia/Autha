use anyhow::Result;

/// `kafka` module contains functionalities related to Kafka communication.
pub mod kafka;
/// `rabbitmq` module contains functionalities related to RabbitMQ communication.
pub mod rabbitmq;

use crate::broker::kafka::KafkaPool;
use crate::broker::rabbitmq::RabbitPool;
use std::sync::Arc;

/// Enumerates the possibilities of usable broker messages.
#[derive(Default, Clone)]
pub enum Broker {
    /// Stores a Kafka pool of connections.
    Kafka(KafkaPool),
    /// Stores a RabbitMQ pool of connections.
    RabbitMQ(RabbitPool),
    /// Stores a non-connected broker.
    #[default]
    None,
}

impl From<Arc<Broker>> for Broker {
    fn from(arc_broker: Arc<Broker>) -> Self {
        match Arc::try_unwrap(arc_broker) {
            Ok(inner_broker) => inner_broker,
            Err(_) => Broker::None,
        }
    }
}

/// Create a new empty `Broker` representation.
pub fn empty() -> Broker {
    Broker::default()
}

/// Creates a new instance of `Broker` using Kafka.
///
/// # Arguments
///
/// * `hosts` - A vector of strings representing Kafka broker hosts.
/// * `pool_size` - The size of the connection pool for Kafka.
///
/// # Returns
///
/// A Result containing a new instance of `Broker` with a Kafka connection pool.
pub fn with_kafka(hosts: Vec<String>, pool_size: u32) -> Result<Broker> {
    Ok(Broker::Kafka(KafkaPool {
        connection: kafka::init(hosts, pool_size)?,
    }))
}

/// Creates a new instance of `Broker` using RabbitMQ.
///
/// # Arguments
///
/// * `hosts` - A vector of strings representing RabbitMQ broker hosts.
/// * `pool_size` - The size of the connection pool for RabbitMQ.
///
/// # Returns
///
/// A Result containing a new instance of `Broker` with a RabbitMQ connection pool.
pub fn with_rabbitmq(hosts: Vec<String>, pool_size: u32) -> Result<Broker> {
    Ok(Broker::RabbitMQ(RabbitPool {
        connection: rabbitmq::init(hosts, pool_size)?,
    }))
}
