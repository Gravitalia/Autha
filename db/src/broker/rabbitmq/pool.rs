use futures_executor::block_on;
use lapin::protocol::{AMQPError, AMQPErrorKind, AMQPHardError};
use lapin::types::ShortString;
use lapin::{Connection, ConnectionProperties, ConnectionState, Error};

pub struct LapinConnectionManager {
    amqp_address: String,
    conn_properties: ConnectionProperties,
}

impl LapinConnectionManager {
    /// Creates a new `LapinConnectionManager`.
    pub fn new(
        amqp_address: &str,
        conn_properties: &ConnectionProperties,
    ) -> Self {
        Self {
            amqp_address: amqp_address.to_string(),
            conn_properties: conn_properties.clone(),
        }
    }

    /// Init a new connection to RabbitMQ.
    async fn async_connect(
        amqp_address: &str,
        conn_properties: ConnectionProperties,
    ) -> Result<Connection, Error> {
        lapin::Connection::connect(amqp_address, conn_properties).await
    }
}

impl r2d2::ManageConnection for LapinConnectionManager {
    type Connection = Connection;
    type Error = Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        block_on(Self::async_connect(
            &self.amqp_address,
            self.conn_properties.clone(),
        ))
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        let valid_states = [
            ConnectionState::Initial,
            ConnectionState::Connecting,
            ConnectionState::Connected,
        ];
        if valid_states.contains(&conn.status().state()) {
            Ok(())
        } else {
            Err(Self::Error::ProtocolError(AMQPError::new(
                AMQPErrorKind::Hard(AMQPHardError::CONNECTIONFORCED),
                ShortString::from("Invalid connection"),
            )))
        }
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        let broken_states =
            [ConnectionState::Closed, ConnectionState::Error];
        broken_states.contains(&conn.status().state())
    }
}
