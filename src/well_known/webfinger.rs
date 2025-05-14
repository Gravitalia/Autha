//! Based on WebFinger (RFC 7033 <https://datatracker.ietf.org/doc/html/rfc7033>).
//!
//! Path: /.well-known/webfinger?resource=acct:VANITY[@domain.tld]

use axum::extract::Query;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::config::Configuration;
use crate::{database::Database, user::User};

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
    State(db): State<Database>,
    State(config): State<Configuration>,
    query: Query<Params>,
) -> Result<impl IntoResponse, StatusCode> {
    // Extract vanity from resource query.
    let resource = query
        .resource
        .strip_prefix("acct:")
        .ok_or(StatusCode::BAD_REQUEST)?;
    let (vanity, _domain) = resource.split_once('@').ok_or(StatusCode::BAD_REQUEST)?;

    let user = User::default()
        .with_id(vanity.to_owned())
        .get(&db.postgres)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // Parse given production URL.
    // Then add a custom path pointing to API.
    let mut url =
        url::Url::parse(&config.address).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    url.set_path(&format!("/users/{}", user.id));

    let response = Response {
        subject: format!(
            "acct:{}@{}",
            user.id,
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
