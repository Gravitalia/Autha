use kafka::producer::{Producer, Record, RequiredAcks};
use kafka::Error;
use std::fmt::Write;
use std::time::Duration;
pub extern crate r2d2;

#[derive(Debug, Clone)]
pub struct KafkaConnectionManager {
    urls: Vec<String>,
}

impl KafkaConnectionManager {
    /// Creates a new `KafkaConnectionManager`.
    ///
    /// See `kafka::producer::Producer` for a description of the parameter
    /// types.
    pub fn new(urls: Vec<String>) -> KafkaConnectionManager {
        KafkaConnectionManager { urls }
    }
}

impl r2d2::ManageConnection for KafkaConnectionManager {
    type Connection = Producer;
    type Error = Error;

    fn connect(&self) -> Result<Producer, Error> {
        Producer::from_hosts(self.urls.clone())
            .with_ack_timeout(Duration::from_secs(1))
            .with_required_acks(RequiredAcks::One)
            .create()
    }

    fn is_valid(&self, connection: &mut Producer) -> Result<(), Error> {
        let mut buf = String::with_capacity(1);
        let _ = write!(&mut buf, "{}", 0);

        connection.send(&Record::from_value("test", buf))
    }

    fn has_broken(&self, _connection: &mut Producer) -> bool {
        false
    }
}
