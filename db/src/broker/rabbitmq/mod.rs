mod pool;

use anyhow::Result;
use async_trait::async_trait;
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

/// Define a trait for the RabbitManager with methods to interact with RabbitMQ.
#[async_trait]
pub trait RabbitManager {
    /// Publish datas to a topic with RabbitMQ.
    async fn publish(&self, topic: &str, content: &str) -> Result<()>;
}

#[async_trait]
impl RabbitManager for RabbitPool {
    async fn publish(&self, topic: &str, content: &str) -> Result<()> {
        let connection = self.connection.get().map_err(|error| {
            log::error!("Error while getting connection: {:?}", error);
            error
        })?;

        let channel = connection.create_channel().await?;

        channel
            .basic_publish(
                "",
                topic,
                BasicPublishOptions::default(),
                content.as_bytes(),
                BasicProperties::default(),
            )
            .await?
            .await?; // Wait for this specific ack/nack.

        Ok(())
    }
}

/// Initialize the connection pool for RabbitMQ.
pub(super) fn init(hosts: Vec<String>, pool_size: u32) -> Result<Pool<LapinConnectionManager>> {
    let manager = pool::LapinConnectionManager::new(&hosts[0], &ConnectionProperties::default());

    Ok(r2d2::Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(1))
        .build(manager)?)
}
