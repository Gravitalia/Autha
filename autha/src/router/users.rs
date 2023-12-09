use anyhow::Result;
use db::memcache::{MemcacheManager, MemcachePool};
use db::scylla::Scylla;
use warp::reply::{Json, WithStatus};

/// Handle get user route.
/// This route allow using ID parameters as "@me" to get actual users.
pub async fn get(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    mut id: String,
    token: Option<String>,
) -> Result<WithStatus<Json>> {
    if id == "@me" {
        if let Some(tok) = token {
            id = match crate::helpers::token::get(&scylla, tok).await {
                Ok(vanity) => vanity,
                Err(e) => {
                    eprintln!("{}", e);
                    return Ok(super::err(super::INVALID_TOKEN))
                },
            }
        } else {
            return Ok(super::err(super::MISSING_AUTHORIZATION_HEADER));
        }
    }

    println!("{}", id);

    Ok(super::err("r"))
}
