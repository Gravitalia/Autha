use anyhow::Result;
use db::scylla::Scylla;
use std::sync::Arc;
use warp::reply::{Json, WithStatus};

/// Handle creation of `access_token` from a refresh token.
pub async fn refresh_token(
    scylla: Arc<Scylla>,
    body: crate::model::body::OAuth,
) -> Result<WithStatus<Json>> {
    let refresh_token = if let Some(token) = body.refresh_token {
        token
    } else {
        return Ok(crate::router::err("Missing refresh_token"));
    };

    let rows = scylla
        .connection
        .query(
            "SELECT user_id, bot_id, scope, deleted FROM accounts.oauth WHERE id = ?",
            vec![&refresh_token],
        )
        .await?
        .rows_typed::<(String, String, Vec<String>, bool)>()?
        .collect::<Vec<_>>();

    if rows.is_empty() {
        return Ok(crate::router::err("Invalid refresh_token"));
    }

    let (user_id, client_id, scopes, deleted) = rows[0].clone()?;

    if deleted {
        return Ok(crate::router::err("Expired refresh_token"));
    }

    // Create access token.
    let (expires_in, access_token) = crate::helpers::token::create_jwt(
        client_id.to_string(),
        user_id,
        scopes.clone(),
    )?;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::AccessToken {
            access_token,
            expires_in,
            refresh_token,
            refresh_token_expires_in: 0,
            scope: scopes.join(" "),
            token_type: "Bearer".to_string(),
        }),
        warp::http::StatusCode::OK,
    ))
}
