use super::{random_string, crypto::encrypt};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::database::cassandra::query;
use anyhow::Result;

/// create allows to add a token into database
pub fn create(user_id: String, ip: String) -> Result<String> {
    let id = random_string(65);
    query(format!("INSERT INTO accounts.tokens (id, user_id, ip, date, expire_at, deleted) VALUES (?, ?, ?, '{}', '{}', false)",
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%:z"), (chrono::Utc::now()+chrono::Duration::days(90)).format("%Y-%m-%d %H:%M:%S%:z")),
    vec![id.clone(), user_id, encrypt(ip.as_bytes())])?;

    Ok(id)
}

/// check allows to verify if token is valid and not
/// expired.
pub fn check(token: String) -> Result<String> {
    let res = query("SELECT expire_at, user_id, deleted FROM accounts.tokens WHERE id = ?", vec![token])?.get_body()?.as_cols().unwrap().rows_content.clone();
    if res.is_empty() {
        return Err(anyhow::Error::msg("not exists"));
    }

    if u64::from_be_bytes(res[0][0].clone().into_plain().unwrap().try_into().unwrap_or_default()) <= SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64 {
        return Err(anyhow::Error::msg("expired"));
    } else if res[0][2].clone().into_plain().unwrap()[..] != [0] {
        return Err(anyhow::Error::msg("revoked"));
    }

    Ok(std::str::from_utf8(&res[0][1].clone().into_plain().unwrap()[..])?.to_string())
}