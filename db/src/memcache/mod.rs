mod pool;

use anyhow::{anyhow, Result};
use r2d2::Pool;
use pool::MemcacheConnectionManager;

/// Represents the value to be stored in Memcached, which can be either a string or a number.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SetValue {
    /// Stores a value as a string of characters.
    Characters(String),
    /// Stores a value as a 16-bit unsigned number.
    Number(u16),
}

impl From<String> for SetValue {
    /// Implements conversion from a String to SetValue, storing the value as a string of characters.
    fn from(s: String) -> Self {
        SetValue::Characters(s)
    }
}

impl From<u16> for SetValue {
    /// Implements conversion from a 16-bit unsigned number to SetValue, storing the value as a Number.
    fn from(n: u16) -> Self {
        SetValue::Number(n)
    }
}

/// Define a structure to manage the Memcached connection pool.
#[derive(Clone, Debug)]
pub struct MemcachePool {
    /// Optional pool of Memcached connections.
    pub connection: Option<Pool<MemcacheConnectionManager>>,
}

/// Define a trait for the MemcacheManager with methods to interact with Memcached.
pub trait MemcacheManager {
    /// Get data from a given key.
    fn get<T: ToString>(&self, key: T) -> Result<Option<String>>;
    /// Set data in Memcached and return the key.
    fn set<T: ToString, V: Into<SetValue> + Clone>(&self, key: T, value: V) -> Result<String>;
    /// Delete data based on the key.
    fn delete<T: ToString>(&self, key: T) -> Result<()>;
}

impl MemcacheManager for MemcachePool {
    /// Retrieve data from Memcached based on the key.
    fn get<T: ToString>(&self, key: T) -> Result<Option<String>> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("No connection pool"))?
            .get()
            .map_err(|error| {
                log::error!("Error while getting connection: {:?}", error);
                error
            })?;

        connection
            .get(&key.to_string())
            .map(|data| {
                log::trace!("Cache data got with key {}", key.to_string());
                data
            })
            .map_err(|error| {
                log::error!("Error while retrieving data: {:?}", error);
                error.into()
            })
    }

    /// Store data in Memcached and return the key.
    fn set<T: ToString, V: Into<SetValue> + Clone>(&self, key: T, value: V) -> Result<String> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("No connection pool"))?
            .get()
            .map_err(|error| {
                log::error!("Error while getting connection: {:?}", error);
                error
            })?;

        let result = match value.clone().into() {
            SetValue::Characters(data) => connection.set(&key.to_string(), data, 300),
            SetValue::Number(data) => connection.set(&key.to_string(), data, 300),
        };

        result
            .map(move |_| {
                log::trace!(
                    "Cache data set with key {} and content as {:?}",
                    key.to_string(),
                    value.into()
                );
                key.to_string()
            })
            .map_err(|error| {
                log::error!("Error while setting data: {:?}", error);
                error.into()
            })
    }

    /// Delete data from Memcached based on the key.
    fn delete<T: ToString>(&self, key: T) -> Result<()> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("No connection pool"))?
            .get()
            .map_err(|error| {
                log::error!("Error while getting connection: {:?}", error);
                error
            })?;

        connection
            .delete(&key.to_string())
            .map(move |_| {
                log::trace!("Cache deleted with key {}", key.to_string());
            })
            .map_err(|error| {
                log::error!("Error while deleting data: {:?}", error);
                error
            })?;

        Ok(())
    }
}

/// Initialize the connection pool for Memcached.
pub fn init(hosts: Vec<String>, pool_size: u32) -> Result<Pool<MemcacheConnectionManager>> {
    let manager = pool::MemcacheConnectionManager::new(format!(
        "memcache://{}?timeout=2&use_udp=true",
        hosts[0]
    ));

    Ok(pool::r2d2::Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(2))
        .build(manager)?)
}
