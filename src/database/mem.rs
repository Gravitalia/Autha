use memcache::{Client, MemcacheError};

pub enum SetValue {
    Characters(String),
    Number(u16),
}

// Inits memcached database connection
pub fn init() -> Result<Client, MemcacheError> {
    memcache::connect(
        format!(
            "memcache://{}?timeout=2&tcp_nodelay=true",
            std::env::var("MEMCACHED_HOST").unwrap_or_else(|_| "127.0.0.1:11211".to_string())
        )
    )
}

// Set data into memcached, and then, returns the key
pub fn set(client: Client, key: String, value: SetValue) -> Result<String, MemcacheError> {
    match value {
        SetValue::Characters(data) => {
            client.set(&key, data, 300)?;
        },
        SetValue::Number(data) => {
            client.set(&key, data, 300)?;
        }
    };

    Ok(key)
}

// This functions allows to get data from a key
pub fn get(client: Client, key: String) -> Result<Option<String>, MemcacheError> {
    let value: Option<String> = client.get(&key)?;

    Ok(value)
}

// This function allows to delete data based on the key
pub fn del(client: Client, key: String) -> Result<(), MemcacheError> {
    client.delete(&key)?;

    Ok(())
}