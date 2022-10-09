extern crate redis;
use redis::Commands;

pub fn init() -> redis::RedisResult<redis::Connection> {
    let client = redis::Client::open("redis://127.0.0.1/")?;

    Ok(client.get_connection().unwrap())
}

pub fn set(mut con: redis::Connection, key: &'static str, value: &'static str) -> redis::RedisResult<()> {
    con.set(key, value)?;

    Ok(())
}

pub fn get(mut con: redis::Connection, key: &'static str) -> redis::RedisResult<String> {
    con.get(key)
}