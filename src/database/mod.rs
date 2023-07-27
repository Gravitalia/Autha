pub mod mem;
pub mod nats;
pub mod scylla;

use crate::helpers::crypto::{decrypt, fpe_decrypt};
use anyhow::{anyhow, Result};
use std::sync::Arc;

// Define queries to get user or bot
const GET_USER: &str = "SELECT username, avatar, bio, deleted, flags, email, birthdate, verified FROM accounts.users WHERE vanity = ?;";
const GET_BOT: &str = "SELECT username, avatar, bio, deleted, flags FROM accounts.bots WHERE id = ?;";

/// Tries to find a user in cache or use database
pub async fn get_user(
    scylla_conn: Arc<crate::Session>,
    memcached: Option<Arc<memcache::Client>>,
    vanity: String,
    requester: String,
) -> Result<(bool, crate::model::user::User)> {
    if let Some(mem_conn) = memcached {
        let data = mem::get(mem_conn, vanity.clone())?.unwrap_or_default();
        if !data.is_empty() && requester != vanity {
            Ok((
                true,
                serde_json::from_str::<crate::model::user::User>(&data[..])?,
            ))
        } else {
            Ok((
                false,
                fallback_scylla(scylla_conn, vanity, requester).await?,
            ))
        }
    } else {
        Ok((
            false,
            fallback_scylla(scylla_conn, vanity, requester).await?,
        ))
    }
}

// Get user via ScyllaDB (or cassandra) without using cache
async fn fallback_scylla(
    scylla_conn: Arc<crate::Session>,
    vanity: String,
    requester: String,
) -> Result<crate::model::user::User> {
    let mut is_bot = false;
    let mut query_result =
        scylla::query(Arc::clone(&scylla_conn), GET_USER, vec![vanity.clone()])
            .await?
            .rows
            .unwrap_or_default();

    if query_result.is_empty() {
        is_bot = true;
        query_result = scylla::query(
            Arc::clone(&scylla_conn),
            GET_BOT,
            vec![vanity.clone()],
        )
        .await?
        .rows
        .unwrap_or_default();
    }

    if query_result.is_empty() {
        Ok(crate::model::user::User {
            username: "".to_string(),
            vanity: "".to_string(),
            avatar: None,
            bio: None,
            email: None,
            birthdate: None,
            deleted: false,
            flags: 0,
            verified: false,
            phone: None,
            password: None,
        })
    } else {
        Ok(crate::model::user::User {
            username: query_result[0].columns[0]
                .as_ref()
                .ok_or_else(|| anyhow!("No reference"))?
                .as_text()
                .ok_or_else(|| anyhow!("Can't convert to string"))?
                .to_string(),
            avatar: if query_result[0].columns[1].is_none() {
                None
            } else {
                let avatar = query_result[0].columns[1]
                    .as_ref()
                    .ok_or_else(|| anyhow!("No reference"))?
                    .as_text()
                    .ok_or_else(|| anyhow!("Can't convert to string"))?
                    .to_string();
                if avatar.is_empty() {
                    None
                } else {
                    Some(avatar)
                }
            },
            bio: if query_result[0].columns[2].is_none() {
                None
            } else {
                let bio = query_result[0].columns[2]
                    .as_ref()
                    .ok_or_else(|| anyhow!("No reference"))?
                    .as_text()
                    .ok_or_else(|| anyhow!("Can't convert to string"))?
                    .to_string();
                if bio.is_empty() {
                    None
                } else {
                    Some(bio)
                }
            },
            email: if vanity == requester && !is_bot {
                Some(fpe_decrypt(
                    query_result[0].columns[5]
                        .as_ref()
                        .ok_or_else(|| anyhow!("No reference"))?
                        .as_text()
                        .ok_or_else(|| anyhow!("Can't convert to string"))?
                        .to_string(),
                )?)
            } else {
                None
            },
            birthdate: if vanity != requester
                || is_bot
                || query_result[0].columns[6].is_none()
            {
                None
            } else {
                let birth = query_result[0].columns[6]
                    .as_ref()
                    .ok_or_else(|| anyhow!("No reference"))?
                    .as_text()
                    .ok_or_else(|| anyhow!("Can't convert to string"))?
                    .to_string();
                if birth.is_empty() {
                    None
                } else {
                    Some(decrypt(scylla_conn, birth).await?)
                }
            },
            deleted: query_result[0].columns[3]
                .as_ref()
                .ok_or_else(|| anyhow!("No reference"))?
                .as_boolean()
                .ok_or_else(|| anyhow!("Can't convert to bool"))?,
            flags: u8::try_from(
                query_result[0].columns[4]
                    .as_ref()
                    .ok_or_else(|| anyhow!("No reference"))?
                    .as_int()
                    .ok_or_else(|| anyhow!("Can't convert to int"))?,
            )
            .ok()
            .unwrap_or_default(),
            verified: if is_bot {
                true
            } else {
                query_result[0].columns[7]
                    .as_ref()
                    .ok_or_else(|| anyhow!("No reference"))?
                    .as_boolean()
                    .ok_or_else(|| anyhow!("Can't convert to bool"))?
            },
            vanity,
            phone: None,
            password: None,
        })
    }
}
