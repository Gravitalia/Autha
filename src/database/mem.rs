use memcache::{Client, MemcacheError};
use once_cell::sync::OnceCell;

/// SESSION represents Memcached active session
static SESSION: OnceCell<Client> = OnceCell::new();

/// SetValue is used to define a value in memcached using a string or a number.
pub enum SetValue {
    Characters(String),
    Number(u16),
}

/// Inits memcached database connection
pub fn init() -> Result<Client, MemcacheError> {
    memcache::connect(format!(
        "memcache://{}?timeout=2&tcp_nodelay=true",
        std::env::var("MEMCACHED_HOST")
            .unwrap_or_else(|_| "127.0.0.1:11211".to_string())
    ))
}

/// Set data into memcached, and then, returns the key
pub fn set(
    key: String,
    value: SetValue,
) -> Result<String, MemcacheError> {
    match value {
        SetValue::Characters(data) => {
            SESSION.get().unwrap().set(&key, data, 300)?;
        }
        SetValue::Number(data) => {
            SESSION.get().unwrap().set(&key, data, 300)?;
        }
    };

    Ok(key)
}

/// This functions allows to get data from a key
pub fn get(
    key: String,
) -> Result<Option<String>, MemcacheError> {
    let value: Option<String> = SESSION.get().unwrap().get(&key)?;

    Ok(value)
}

/// This function allows to delete data based on the key
pub fn del(key: String) -> Result<(), MemcacheError> {
    SESSION.get().unwrap().delete(&key)?;

    Ok(())
}
