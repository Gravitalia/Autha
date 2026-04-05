//! Custom state for Axum.

use std::sync::Arc;

use application::ports::inbound::{
    Authenticate, CreateAccount, GetUser, Status,
};
use axum::extract::FromRef;

/// Shared state.
#[derive(Clone)]
pub struct AppState {
    pub status: Arc<dyn Status>,
    pub create_account: Arc<dyn CreateAccount>,
    pub authenticate: Arc<dyn Authenticate>,
    pub get_user: Arc<dyn GetUser>,
}

impl FromRef<AppState> for Arc<dyn Status> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.status)
    }
}

impl FromRef<AppState> for Arc<dyn CreateAccount> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.create_account)
    }
}

impl FromRef<AppState> for Arc<dyn Authenticate> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.authenticate)
    }
}

impl FromRef<AppState> for Arc<dyn GetUser> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.get_user)
    }
}
