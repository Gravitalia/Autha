use super::queries::CREATE_TOKEN;
use anyhow::{bail, Result};
use db::scylla::Scylla;
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

const JWT_TIME: u64 = 3600; // 1 hour.
const TOKEN_LENGTH: usize = 65;

/// Json Web Token payload as structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Recipient of the token.
    /// Diverges from the "aud" (audience) since it is not required to validate it.
    pub client_id: String,
    /// Time after which the JWT expires.
    pub exp: u64,
    /// Issuer of the JWT.
    pub iss: String,
    /// Time at which the JWT was issued.
    pub iat: u64,
    /// Custom claim. Granted permissions to the token.
    pub scope: Vec<String>,
    /// Subject of the JWT. User unique identifier called `vanity`.
    pub sub: String,
}

/// Create a 14-day valid user token into database.
/// It must be saved securely because of its impact on the data it deserves.
pub async fn create(
    scylla: &Arc<Scylla>,
    user_id: &String,
    ip: String,
) -> Result<String> {
    let id = crypto::random_string(TOKEN_LENGTH);

    // Get actual timestamp to save exact date of connection.
    let timestamp =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

    // Encrypt IP adress before save it.
    let (nonce, encrypted) =
        crypto::encrypt::chacha20_poly1305(ip.as_bytes().to_vec())?;
    let uuid = uuid::Uuid::new_v4().to_string();

    scylla
        .connection
        .query(
            "INSERT INTO accounts.salts ( id, salt ) VALUES (?, ?)",
            (&uuid, &nonce),
        )
        .await?;

    if let Some(query) = CREATE_TOKEN.get() {
        scylla
            .connection
            .execute(
                query,
                (
                    &id,
                    &user_id,
                    &format!("{}//{}", uuid, encrypted),
                    db::libscylla::frame::value::CqlTimestamp(timestamp),
                ),
            )
            .await?;
    } else {
        error!("Prepared queries do not appear to be initialized.");
    }

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

    let (vanity, deleted) = rows[0].clone().unwrap_or_default();

    if deleted {
        bail!("revoked token")
    }

    Ok(vanity)
}

/// Create a Json Web Token for access token during seven days.
pub fn create_jwt(
    client_id: String,
    user_id: String,
    scope: Vec<String>,
) -> Result<(u64, String)> {
    let private_key = EncodingKey::from_rsa_pem(
        std::env::var("RSA_PRIVATE_KEY")?.as_bytes(),
    )?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;

    Ok((
        JWT_TIME,
        encode(
            &Header::new(Algorithm::RS256),
            &Claims {
                client_id,
                sub: user_id,
                scope,
                exp: now.as_secs() + JWT_TIME,
                iss: "https://account.gravitalia.com".to_string(),
                iat: now.as_secs(),
            },
            &private_key,
        )?,
    ))
}

/// Retrieves JSON data from the JWT and checks whether the token is valid.
pub fn get_jwt(token: &str) -> Result<Claims> {
    let public_key =
        DecodingKey::from_rsa_pem(std::env::var("RSA_PUBLIC_KEY")?.as_bytes())?;

    let data = decode::<Claims>(
        token,
        &public_key,
        &Validation::new(Algorithm::RS256),
    )?;

    if data.claims.exp
        <= std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    {
        bail!("expired token")
    }

    Ok(data.claims)
}
