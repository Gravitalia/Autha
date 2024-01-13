use anyhow::Result;

/// `kafka` module contains functionalities related to Kafka communication.
pub mod kafka;

use crate::broker::kafka::KafkaPool;

/// Enumerates the possibilities of usable broker messages.
pub enum Broker {
    /// Stores a Kafka pool of connections.
    Kafka(KafkaPool),
    /// Stores a RabbitMQ pool of connections.
    RabbitMQ(()),
}

impl From<KafkaPool> for Broker {
    fn from(k: KafkaPool) -> Self {
        Broker::Kafka(k)
    }
}

impl From<()> for Broker {
    fn from(_r: ()) -> Self {
        unimplemented!()
    }
}

/// Structure representing a set of brokers.
#[derive(Debug, Clone)]
pub struct Brokers<B: Into<Broker> + Clone> {
    /// The optional broker instance.
    pub broker: Option<B>,
    /// The list of hosts for the brokers.
    pub hosts: Vec<String>,
    /// The size of the connection pool.
    pub pool_size: u32,
}

impl<B> Brokers<B>
where
    B: Into<Broker> + Clone,
{
    /// Creates a new instance of `Brokers`.
    pub fn new(hosts: Vec<String>, pool_size: u32) -> Self {
        Brokers {
            broker: None,
            hosts,
            pool_size,
        }
    }
}

/// Trait for managing different types of brokers.
pub trait BrokersManager {
    /// Establishes a connection with Kafka pools.
    fn use_kafka(&mut self) -> Result<Brokers<KafkaPool>>;
}

impl<B> BrokersManager for Brokers<B>
where
    B: Into<Broker> + Clone,
{
    fn use_kafka(&mut self) -> Result<Brokers<KafkaPool>> {
        let new_kafka_connection = kafka::init(self.hosts.clone(), self.pool_size)?;

        Ok(Brokers {
            broker: Some(kafka::KafkaPool {
                connection: new_kafka_connection,
            }),
            hosts: self.hosts.clone(),
            pool_size: self.pool_size,
        })
    }
}
