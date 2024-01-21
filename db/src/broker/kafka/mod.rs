mod pool;

use anyhow::Result;
use pool::KafkaConnectionManager;
use r2d2::Pool;

/// Define a structure to manage the Kafka broker connection pool.
#[derive(Clone, Debug)]
pub struct KafkaPool {
    /// Pool of Kafka connections.
    pub connection: Pool<KafkaConnectionManager>,
}

/// Define a trait for the KafkaManager with methods to interact with Kafka.
pub trait KafkaManager {
    /// Publish datas to a topic with Kafka.
    fn publish(&self, topic: &str, content: &str) -> Result<()>;
}

impl KafkaManager for KafkaPool {
    fn publish(&self, topic: &str, content: &str) -> Result<()> {
        let mut connection = self.connection.get().map_err(|error| {
            #[cfg(feature = "logging")]
            log::error!("Error while getting connection: {:?}", error);

            error
        })?;

        connection
            .send(&kafka::producer::Record {
                topic,
                partition: -1,
                key: (),
                value: content,
            })
            .map(|_| {
                #[cfg(feature = "logging")]
                log::trace!("Message sent to topic {} with Kafka", topic);
            })
            .map_err(|error| {
                #[cfg(feature = "logging")]
                log::error!(
                    "Error during message broking with Kafka: {:?}",
                    error
                );

                error.into()
            })
    }
}

/// Initialize the connection pool for Kafka.
pub(super) fn init(
    hosts: Vec<String>,
    pool_size: u32,
) -> Result<Pool<KafkaConnectionManager>> {
    let manager = pool::KafkaConnectionManager::new(hosts);

    Ok(pool::r2d2::Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(2))
        .build(manager)?)
}
