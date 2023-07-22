use super::{random_string, crypto::encrypt};
use std::{time::{SystemTime, UNIX_EPOCH}, sync::Arc};
use crate::database::scylla::query;
use anyhow::Result;
use scylla::Session;

/// create allows to add a token into database
pub async fn create(scylla: Arc<Session>, user_id: String, ip: String) -> Result<String> {
    let id = random_string(65);

    query(
        scylla.clone(),
        "INSERT INTO accounts.tokens (id, user_id, ip, date, expire_at, deleted) VALUES (?, ?, ?, ?, ?, false)",
        (
                id.clone(),
                user_id,
                encrypt(scylla, ip.as_bytes()).await,
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%:z").to_string(),
                (chrono::Utc::now()+chrono::Duration::days(90)).format("%Y-%m-%d %H:%M:%S%:z").to_string()
            )
    ).await?;

    Ok(id)
}

/// check allows to verify if token is valid and not expired
pub async fn check(scylla: Arc<Session>, token: String) -> Result<String> {
    let res = query(scylla, "SELECT expire_at, user_id, deleted FROM accounts.tokens WHERE id = ?", vec![token]).await?.rows.unwrap_or_default();

    if res.is_empty() {
        return Err(anyhow::Error::msg("not exists"));
    }

    if res[0].columns[0].as_ref().unwrap().as_bigint().unwrap() as u128 <= SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() {
        return Err(anyhow::Error::msg("expired"));
    } else if res[0].columns[2].as_ref().unwrap().as_boolean().unwrap() == true {
        return Err(anyhow::Error::msg("revoked"));
    }

    Ok(
        res[0].columns[1].as_ref().unwrap().as_text().unwrap().to_string()
    )
}