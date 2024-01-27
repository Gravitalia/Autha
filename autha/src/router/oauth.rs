use anyhow::Result;
use db::memcache::{MemcacheManager, MemcachePool};
use db::scylla::Scylla;
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

/// Route to create an authorization code to obtain an access token.
pub async fn create(
    scylla: Arc<Scylla>,
    memcached: MemcachePool,
    query: crate::model::query::OAuth,
    token: String,
) -> Result<WithStatus<Json>> {
    let id = match crate::helpers::token::get(&scylla, &token).await {
        Ok(vanity) => vanity,
        Err(_) => {
            return Ok(super::err(super::INVALID_TOKEN));
        },
    };

    let user =
        match crate::router::users::get_user(&scylla, &memcached, &id).await {
            Ok(user) => user,
            Err(error) => {
                log::error!("Failed retrieving user: {}", error);
                return Ok(super::err(super::INTERNAL_SERVER_ERROR));
            },
        };

    let bot = scylla
        .connection
        .query(
            "SELECT deleted, redirect_url FROM accounts.bots WHERE id = ?",
            vec![&query.client_id],
        )
        .await?
        .rows_typed::<(bool, Vec<String>)>()?
        .collect::<Vec<_>>();

    // Check if bot exists.
    if bot.is_empty() {
        return Ok(super::err(super::INVALID_BOT));
    }

    let (deleted, redirect_uris) = bot[0].clone().unwrap();

    if deleted {
        return Ok(super::err("Bot has been deleted"));
    } else if redirect_uris.iter().any(|x| x == &query.redirect_uri) {
        return Ok(super::err("Invalid redirect_uri"));
    }

    // Create crypto-secure random 31-character authorization token.
    let id = crypto::random_string(31);

    memcached.set(
        &id,
        format!("{}+{}+{}", query.client_id, query.redirect_uri, user.vanity),
    )?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: id,
        }),
        warp::http::StatusCode::OK,
    ))
}
