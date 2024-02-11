mod pool;

use crate::DbError;
use pool::KafkaConnectionManager;
use r2d2::Pool;

/// Define a structure to manage the Kafka broker connection pool.
#[derive(Clone, Debug)]
pub struct KafkaPool {
    /// Pool of Kafka connections.
    pub connection: Pool<KafkaConnectionManager>,
}

impl KafkaPool {
    /// Publish datas to a topic with Kafka.
    pub fn publish(&self, topic: &str, content: &str) -> Result<(), DbError> {
        let mut connection = self.connection.get().map_err(|error| {
            #[cfg(feature = "logging")]
            log::error!("Error while getting connection: {:?}", error);

            DbError::R2D2(error)
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

                DbError::Kafka(error)
            })
    }
}

/// Initialize the connection pool for Kafka.
pub(super) fn init(
    hosts: Vec<String>,
    pool_size: u32,
) -> Result<Pool<KafkaConnectionManager>, r2d2::Error> {
    let manager = pool::KafkaConnectionManager::new(hosts);

    pool::r2d2::Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(2))
        .build(manager)
}
