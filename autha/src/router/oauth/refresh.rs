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
            "SELECT user_id, scope, deleted FROM accounts.oauth WHERE id = ?",
            vec![&refresh_token],
        )
        .await?
        .rows_typed::<(String, Vec<String>, bool)>()?
        .collect::<Vec<_>>();

    let (user_id, scopes, deleted) = rows[0].clone()?;

    if deleted {
        return Ok(crate::router::err("Expired refresh_token"));
    }

    // Create access token.
    let (expires_in, access_token) =
        crate::helpers::token::create_jwt(user_id, scopes.clone())?;

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
