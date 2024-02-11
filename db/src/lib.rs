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
