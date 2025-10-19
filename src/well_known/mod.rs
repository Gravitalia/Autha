//! Handle well-knowns related.
mod jwks;
mod webfinger;

use axum::Router;
use axum::routing::get;

use crate::AppState;

pub fn well_known(state: AppState) -> Router {
    Router::new()
        .route("/webfinger", get(webfinger::handler))
        .route("/jwks.json", get(jwks::handler))
        .with_state(state)
}
