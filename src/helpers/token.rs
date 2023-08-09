use super::{crypto::encrypt, random_string};
use crate::database::scylla::query;
use anyhow::{anyhow, Result};
use scylla::Session;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

// Set CQL queries
const CREATE_TOKEN: &str = "INSERT INTO accounts.tokens (id, user_id, ip, date, expire_at, deleted) VALUES (?, ?, ?, ?, ?, false);";
const CHECK_TOKEN: &str =
    "SELECT expire_at, user_id, deleted FROM accounts.tokens WHERE id = ?";

/// create allows to add a token into database
pub async fn create(
    scylla: Arc<Session>,
    user_id: String,
    ip: String,
) -> Result<String> {
    let id = random_string(65);

    // Get actual timestamp (since 1st Jan. 1970)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as i64;

    query(
        scylla.clone(),
        CREATE_TOKEN,
        (
            id.clone(),
            user_id,
            encrypt(scylla, ip.as_bytes()).await,
            timestamp,
            timestamp + 777600000, // 90 days in milliseconds
        ),
    )
    .await?;

    Ok(id)
}

/// check allows to verify if token is valid and not expired
pub async fn check(scylla: Arc<Session>, token: String) -> Result<String> {
    let query_response = query(scylla, CHECK_TOKEN, vec![token])
        .await?
        .rows
        .unwrap_or_default();

    if query_response.is_empty() {
        return Err(anyhow::Error::msg("not exists"));
    }

    if query_response[0].columns[0]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_bigint()
        .ok_or_else(|| anyhow!("Can't convert to bigint"))? as u128
        <= SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
    {
        return Err(anyhow::Error::msg("expired"));
    } else if query_response[0].columns[2]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_boolean()
        .ok_or_else(|| anyhow!("Can't convert to bool"))?
    {
        return Err(anyhow::Error::msg("revoked"));
    }

    Ok(query_response[0].columns[1]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_text()
        .ok_or_else(|| anyhow!("Can't convert to string"))?
        .to_string())
}
