use memcache::{Client, MemcacheError};

pub enum SetValue {
    Characters(String),
    Number(u16),
}

pub fn init() -> Result<Client, MemcacheError> {
    memcache::connect("memcache://127.0.0.1:11211?timeout=2&tcp_nodelay=true")
}

pub fn set(session: Client, key: String, value: SetValue) -> Result<(), MemcacheError> {
    match value {
        SetValue::Characters(data) => {
            session.set(&key, data, 300)?;
        },
        SetValue::Number(data) => {
            session.set(&key, data, 300)?;
        }
    };

    Ok(())
}

pub fn get(session: Client, key: String) -> Result<Option<String>, MemcacheError> {
    let value: Option<String> = session.get(&key)?;

    Ok(value)
}
