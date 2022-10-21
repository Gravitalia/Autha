use memcache::{Client, MemcacheError};
use once_cell::sync::OnceCell;
static SESSION: OnceCell<Client> = OnceCell::new();

pub enum SetValue {
    Characters(String),
    Number(u16),
}

pub fn init() {
    let _db = SESSION.set(memcache::connect("memcache://127.0.0.1:11211?timeout=5&tcp_nodelay=true").unwrap());
}

pub fn set(key: String, value: SetValue) -> Result<(), MemcacheError> {
    match value {
        SetValue::Characters(data) => {
            SESSION.get().unwrap().set(&key, data, 300)?;
        },
        SetValue::Number(data) => {
            SESSION.get().unwrap().set(&key, data, 300)?;
        }
    };

    Ok(())
}

pub fn get(key: String) -> Result<Option<String>, MemcacheError> {
    let value: Option<String> = SESSION.get().unwrap().get(&key)?;

    Ok(value)
}