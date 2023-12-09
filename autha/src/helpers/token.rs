use anyhow::{bail, Result};
use db::scylla::Scylla;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Create a 14-day valid user token into database.
/// It must be saved securely because of its impact on the data it deserves.
pub async fn create(scylla: &Arc<Scylla>, user_id: &String, ip: String) -> Result<String> {
    let id = crypto::random_string(65);

    // Get actual timestamp to save exact date of connection.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as i64;

    // Use prepared query to properly balance.
    let insert_token_query = scylla
    .connection
    .prepare(
        "INSERT INTO accounts.tokens (id, user_id, ip, date, deleted) VALUES (?, ?, ?, ?, false)"
    )
    .await?;

    // Encrypt IP adress before save it.
    let (nonce, encrypted) = crypto::encrypt::chacha20_poly1305(ip.as_bytes().to_vec())?;
    let uuid = uuid::Uuid::new_v4().to_string();

    scylla
        .connection
        .query(
            "INSERT INTO accounts.salts ( id, salt ) VALUES (?, ?)",
            (&uuid, &nonce),
        )
        .await?;

    scylla
        .connection
        .execute(
            &insert_token_query,
            (
                &id,
                &user_id,
                &format!("{}//{}", uuid, encrypted),
                &timestamp,
            ),
        )
        .await?;

    Ok(id)
}

/// Verify the existence of a user token into database.
/// Result in error or datas about the token.
pub async fn get(scylla: &Arc<Scylla>, token: String) -> Result<String> {
    let rows = scylla
        .connection
        .query(
            "SELECT expire_at, user_id, deleted FROM accounts.tokens WHERE id = ?",
            vec![token],
        )
        .await?
        .rows_typed::<(i64, String, bool)>()?
        .collect::<Vec<_>>();

    if rows.is_empty() {
        bail!("no token exists")
    }

    let (expire, vanity, deleted) = rows[0].clone().unwrap();

    if expire as u128 <= SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() {
        bail!("expired token");
    } else if deleted {
        bail!("revoked token")
    }

    Ok(vanity)
}
