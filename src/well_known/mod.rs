pub mod webfinger;

use axum::routing::get;
use axum::Router;

use crate::AppState;

pub fn well_known(state: AppState) -> Router {
    Router::new()
        .route("/webfinger", get(webfinger::handler))
        .with_state(state)
}
