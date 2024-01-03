use memcache::MemcacheError;
pub extern crate r2d2;

#[derive(Debug)]
pub struct MemcacheConnectionManager {
    urls: Vec<String>,
}

impl MemcacheConnectionManager {
    /// Creates a new `MemcacheConnectionManager`.
    ///
    /// See `memcache::Connection::connect` for a description of the parameter
    /// types.
    pub fn new<C: memcache::Connectable>(target: C) -> MemcacheConnectionManager {
        MemcacheConnectionManager {
            urls: target.get_urls(),
        }
    }
}

impl r2d2::ManageConnection for MemcacheConnectionManager {
    type Connection = memcache::Client;
    type Error = MemcacheError;

    fn connect(&self) -> Result<memcache::Client, MemcacheError> {
        memcache::Client::connect(self.urls.clone())
    }

    fn is_valid(&self, connection: &mut memcache::Client) -> Result<(), MemcacheError> {
        match connection.version() {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn has_broken(&self, _connection: &mut memcache::Client) -> bool {
        false
    }
}
