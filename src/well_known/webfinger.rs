//! Based on WebFinger (RFC 7033 <https://datatracker.ietf.org/doc/html/rfc7033>).
//!
//! Path: /.well-known/webfinger?resource=acct:VANITY[@domain.tld]

use axum::extract::Query;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::user::UserBuilder;

const HEADER: &str = "application/jrd+json";

#[derive(Debug, Deserialize)]
pub struct Params {
    resource: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    subject: String,
    aliases: Vec<String>,
    links: Vec<Link>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Link {
    rel: String,
    r#type: String,
    href: String,
}

pub async fn handler(
    State(state): State<AppState>,
    query: Query<Params>,
) -> Result<impl IntoResponse, StatusCode> {
    // Extract vanity from resource query.
    let resource = query
        .resource
        .strip_prefix("acct:")
        .ok_or(StatusCode::BAD_REQUEST)?;
    let (vanity, _domain) =
        resource.split_once('@').ok_or(StatusCode::BAD_REQUEST)?;

    let user = UserBuilder::new()
        .id(vanity.to_owned())
        .build(state.db.postgres, state.crypto)
        .find_by_id()
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // Parse given production URL.
    // Then add a custom path pointing to API.
    let mut url = url::Url::parse(&state.config.url)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    url.set_path(&format!("/users/{}", user.data.id));

    let response = Response {
        subject: format!(
            "acct:{}@{}",
            user.data.id,
            url.host().map(|u| u.to_string()).unwrap_or_default()
        ),
        aliases: Vec::new(),
        links: vec![Link {
            rel: "self".into(),
            r#type: "application/activity+json".into(),
            href: url.to_string(),
        }],
    };

    Ok(([(header::CONTENT_TYPE, HEADER)], Json(response)))
}
