//! Route handler module with HTTP routes and validation.

pub mod create;
pub mod login;
pub mod status;
pub mod users;

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::Json;
use serde::de::DeserializeOwned;
use validator::Validate;

use crate::error::ServerError;

/// A wrapper struct for validating form data.
#[derive(Debug, Clone, Copy, Default)]
pub struct Valid<T>(pub T);

impl<T, S> FromRequest<S> for Valid<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = ServerError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(payload) = Json::<T>::from_request(req, state).await?;
        payload.validate()?;
        Ok(Valid(payload))
    }
}
