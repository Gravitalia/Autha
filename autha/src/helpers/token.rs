use anyhow::{bail, Result};
use db::scylla::Scylla;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Json Web Token payload as structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User vanity.
    pub sub: String,
    /// Scope allowed for the token.
    pub scope: Vec<String>,
    /// Expiration date.
    pub exp: u64,
    /// The issuer. Should be gravitalia or autha.
    iss: String,
    /// Issuing date.
    iat: u64,
}

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
pub async fn get(scylla: &Arc<Scylla>, token: &str) -> Result<String> {
    let rows = scylla
        .connection
        .query(
            "SELECT user_id, deleted FROM accounts.tokens WHERE id = ?",
            vec![token],
        )
        .await?
        .rows_typed::<(String, bool)>()?
        .collect::<Vec<_>>();

    if rows.is_empty() {
        bail!("no token exists")
    }

    let (vanity, deleted) = rows[0].clone().unwrap();

    if deleted {
        bail!("revoked token")
    }

    Ok(vanity)
}

/// Retrieves JSON data from the JWT and checks whether the token is valid.
pub fn get_jwt_data(token: &str) -> Result<(String, Vec<String>)> {
    let public_key = DecodingKey::from_rsa_pem(
        std::env::var("RSA_PUBLIC_KEY")
            .expect("Missing env `RSA_PUBLIC_KEY`")
            .as_bytes(),
    )
    .expect("Failed to load public key");

    let claims = decode::<Claims>(token, &public_key, &Validation::new(Algorithm::RS256))?;

    if claims.claims.exp
        <= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    {
        bail!("expired token")
    }

    Ok((claims.claims.sub, claims.claims.scope))
}
