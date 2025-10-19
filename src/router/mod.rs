//! Route handler module with HTTP routes and validation.

pub mod create;
pub mod login;
pub mod status;
pub mod users;

use axum::extract::{FromRequest, Json, Request};
use serde::de::DeserializeOwned;
use validator::Validate;

use crate::error::ServerError;

#[derive(Debug)]
pub struct Valid<T>(pub T);

impl<T, S> FromRequest<S> for Valid<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = ServerError;

    async fn from_request(
        req: Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Json(payload) = Json::<T>::from_request(req, state).await?;
        payload.validate()?;
        Ok(Valid(payload))
    }
}
