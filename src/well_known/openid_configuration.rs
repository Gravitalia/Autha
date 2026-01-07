//! Based on OpenID Connect Discovery.
//! Path: /.well-known/openid-configuration
//!
//! **Autha don't really support OAuth2 for now.**
//! It MAY support it in future, but that's not its primary goal.
//!
//! OpenID MUST supports RS256, but Autha don't.

use std::sync::OnceLock;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::AppState;
use crate::token::SCOPES;

const AUTHORIZATION_ENDPOINT: &str =
    "https://account.gravitalia.com/authorize";
const TOKEN_ENDPOINT: &str = "/users/refresh_token";
const USERINFO_ENDPOINT: &str = "/users/@me";
const JWKS_ENDPOINT: &str = "/.well-known/jwks.json";

static RESPONSE: OnceLock<Response> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    issuer: String,
    authorization_endpoint: String,
    userinfo_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    subject_types_supported: Vec<String>,
}

pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<&'static Response>, StatusCode> {
    if let Some(resp) = RESPONSE.get() {
        return Ok(Json(resp));
    }

    let constructed = build_response(&state)?;
    let response = RESPONSE.get_or_init(|| constructed);

    Ok(Json(response))
}

fn build_response(state: &AppState) -> Result<Response, StatusCode> {
    let base = Url::parse(&state.config.url)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let userinfo = join_url(&base, USERINFO_ENDPOINT)?;
    let token = join_url(&base, TOKEN_ENDPOINT)?;
    let jwks = join_url(&base, JWKS_ENDPOINT)?;

    Ok(Response {
        issuer: state.config.url.clone(),
        authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
        userinfo_endpoint: userinfo,
        token_endpoint: token,
        jwks_uri: jwks,
        response_types_supported: vec!["code".to_string()],
        id_token_signing_alg_values_supported: vec!["ES256".to_string()],
        scopes_supported: SCOPES.clone(),
        subject_types_supported: vec!["public".to_string()],
    })
}

fn join_url(base: &Url, path: &str) -> Result<String, StatusCode> {
    base.join(path)
        .map(|u| u.to_string())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
