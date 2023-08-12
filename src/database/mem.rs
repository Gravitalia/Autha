use anyhow::Result;
use r2d2::Pool;
use r2d2_memcache::MemcacheConnectionManager;

/// Represents pool connection type
pub type MemPool = Pool<MemcacheConnectionManager>;

/// SetValue is used to define a value in memcached using a string or a number.
pub enum SetValue {
    Characters(String),
    Number(u16),
}

/// Inits memcached database connection
pub fn init() -> Result<MemPool> {
    let manager = r2d2_memcache::MemcacheConnectionManager::new(format!(
        "memcache://{}?timeout=2&tcp_nodelay=true",
        std::env::var("MEMCACHED_HOST")
            .unwrap_or_else(|_| "127.0.0.1:11211".to_string())
    ));

    Ok(r2d2_memcache::r2d2::Pool::builder()
        .max_size(
            std::env::var("MEMCACHED_POOL_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse::<u32>()?,
        )
        .min_idle(Some(2))
        .build(manager)?)
}

/// Set data into memcached, and then, returns the key
pub fn set(pool: &MemPool, key: String, value: SetValue) -> Result<String> {
    match value {
        SetValue::Characters(data) => {
            pool.get()?.set(&key, data, 300)?;
        }
        SetValue::Number(data) => {
            pool.get()?.set(&key, data, 300)?;
        }
    };

    Ok(key)
}

/// This functions allows to get data from a key
pub fn get(pool: &MemPool, key: String) -> Result<Option<String>> {
    let value: Option<String> = pool.get()?.get(&key)?;

    Ok(value)
}

/// This function allows to delete data based on the key
pub fn del(pool: &MemPool, key: String) -> Result<()> {
    pool.get()?.delete(&key)?;

    Ok(())
}
