use db::libscylla as scylla;
use db::libscylla::macros::FromRow;
use db::scylla::Scylla;
use serde::Serialize;
use std::{convert::Infallible, sync::Arc};
use warp::http::StatusCode;

use crate::helpers::{queries::GET_USER_REFRESH_TOKEN, token::get_jwt};

/// Represents data related to a saved refresh token.
#[derive(Serialize, FromRow, Debug, Default, Clone)]
struct RefreshToken {
    /// The client ID associated with the token.
    pub bot_id: String,
    /// Indicates whether the refresh token has been deleted.
    pub deleted: bool,
    /// The refresh token ID.
    pub id: String,
    /// The permissions granted by the token.
    pub scope: Vec<String>,
    /// The user's unique identifier.
    pub user_id: String,
}

/// Handle access_token and refresh_token revocation from one of the tokens.
pub async fn revoke(
    scylla: Arc<Scylla>,
    body: crate::model::body::Revoke,
) -> Result<impl warp::Reply, Infallible> {
    if body.token.len() >= super::REFRESH_TOKEN_LENGTH {
        let _ = scylla
            .connection
            .query(
                "DELETE FROM accounts.oauth WHERE id = ? IF EXISTS",
                vec![body.token],
            )
            .await;
    } else {
        let claims = match get_jwt(&body.token) {
            Ok(claims) => claims,
            // Only return status 200 even if it fails as specified on rfc7009.
            Err(_) => {
                return Ok(warp::reply::with_status(
                    warp::reply(),
                    StatusCode::OK,
                ))
            },
        };

        let rows = match scylla
            .connection
            .execute(
                GET_USER_REFRESH_TOKEN.get_or_init(|| unreachable!()),
                vec![claims.sub],
            )
            .await
            .unwrap_or_default()
            .rows_typed::<RefreshToken>()
        {
            Ok(rows) => rows.collect::<Vec<_>>(),
            Err(_) => {
                return Ok(warp::reply::with_status(
                    warp::reply(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            },
        };

        if let Some(Ok(refresh_token)) = rows.iter().find(|row| {
            if let Ok(data) = row {
                !data.deleted
                    && data.bot_id == claims.client_id
                    && claims.scope.eq(&data.scope)
            } else {
                false
            }
        }) {
            let _ = scylla
                .connection
                .query(
                    "DELETE FROM accounts.oauth WHERE id = ?",
                    vec![refresh_token.clone().id],
                )
                .await;
        };
    }

    Ok(warp::reply::with_status(warp::reply(), StatusCode::OK))
}
