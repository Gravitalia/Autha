// Clippy lint.
#![deny(missing_docs)]
//! # db
//!
//! library to simply use databases.
//!
//! Supported databases:
//! - memcached;
//! - scylladb/cassandra.
//! Supported message broker:
//! - kafka/redpanda;
//!
//! # Init memcached database.
//!
//! ```rust
//! let memcached_pool = match db::memcache::init(
//!     vec!["localhost:11211".to_string()],
//!     15,
//! ) {
//!     Ok(pool) => {
//!         db::memcache::MemcachePool {
//!             connection: Some(pool),
//!         }
//!     }
//!     Err(error) => {
//!         panic!("");
//!     }
//! };
//! ```

#[cfg(feature = "memcached")]
extern crate memcache as libmemcache;

#[cfg(feature = "cassandra")]
pub extern crate scylla as libscylla;

/// Handle multiple brokers.
pub mod broker;
/// Memcached database handler.
#[cfg(feature = "memcached")]
pub mod memcache;
/// Scylla database handler.
#[cfg(feature = "cassandra")]
pub mod scylla;

use std::error::Error;
use std::fmt;

/// Error type for databases errors.
#[derive(Debug)]
pub enum DbError {
    /// An error with absolutely no details.
    Unspecified,
    /// Related to R2D2.
    R2D2(r2d2::Error),
    /// Related to Kafka.
    #[cfg(feature = "apache_kafka")]
    Kafka(kafka::Error),
    /// Related to RabbitMQ.
    #[cfg(feature = "rabbitmq")]
    RabbitMQ(lapin::Error),
    /// Related to memcached.
    #[cfg(feature = "memcached")]
    Memcached(libmemcache::MemcacheError),
    /// Unreachable pool connection.
    NoPool,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DbError::Unspecified => write!(f, "Unknown error"),
            DbError::R2D2(error) => write!(f, "{error}"),
            DbError::Kafka(error) => write!(f, "{error}"),
            #[cfg(feature = "rabbitmq")]
            DbError::RabbitMQ(error) => write!(f, "{error}"),
            #[cfg(feature = "memcached")]
            DbError::Memcached(error) => write!(f, "{error}"),
            DbError::NoPool => write!(f, "No connection pool"),
        }
    }
}

impl Error for DbError {}
