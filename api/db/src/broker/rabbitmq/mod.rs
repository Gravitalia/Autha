mod pool;

use crate::DbError;
use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, ConnectionProperties};
use pool::LapinConnectionManager;
use r2d2::Pool;

/// Define a structure to manage the RabbitMQ broker connection pool.
#[derive(Clone)]
pub struct RabbitPool {
    /// Pool of RabbitMQ connections.
    pub connection: Pool<LapinConnectionManager>,
}

impl RabbitPool {
    /// Publish datas to a topic with RabbitMQ.
    pub async fn publish(
        &self,
        topic: &str,
        content: &str,
    ) -> Result<(), DbError> {
        let connection = self.connection.get().map_err(|error| {
            #[cfg(feature = "logging")]
            log::error!("Error while getting connection: {:?}", error);

            DbError::Unspecified
        })?;

        let channel = connection
            .create_channel()
            .await
            .map_err(DbError::RabbitMQ)?;

        channel
            .basic_publish(
                "",
                topic,
                BasicPublishOptions::default(),
                content.as_bytes(),
                BasicProperties::default(),
            )
            .await
            .map_err(DbError::RabbitMQ)?
            .await // Wait for this specific ack/nack.
            .map_err(DbError::RabbitMQ)?;

        Ok(())
    }
}

/// Initialize the connection pool for RabbitMQ.
pub(super) fn init(
    hosts: Vec<String>,
    pool_size: u32,
) -> Result<Pool<LapinConnectionManager>, r2d2::Error> {
    let manager = pool::LapinConnectionManager::new(
        &hosts[0],
        &ConnectionProperties::default(),
    );

    r2d2::Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(1))
        .build(manager)
}
