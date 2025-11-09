//! Route handler module with HTTP routes and validation.

pub mod create;
pub mod login;
pub mod status;
pub mod users;

use axum::extract::{FromRef, FromRequest, Json, Request};
use regex_lite::Regex;
use serde::de::DeserializeOwned;
use validator::{Validate, ValidateArgs, ValidationError};

use crate::error::ServerError;

use std::sync::LazyLock;

static VANITY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]+$").unwrap());

/// Validate axum `Body` without state.
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

/// Validate axum `Body` with state.
#[derive(Debug)]
pub struct ValidWithState<T>(pub T);

impl<T, S, A> FromRequest<S> for ValidWithState<T>
where
    T: for<'v> ValidateArgs<'v, Args = &'v A> + DeserializeOwned,
    S: Send + Sync,
    A: Send + Sync + FromRef<S>,
{
    type Rejection = ServerError;

    async fn from_request(
        req: Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Json(payload) = Json::<T>::from_request(req, state).await?;
        let args: A = FromRef::from_ref(state);
        payload.validate_with_args(&args)?;
        Ok(ValidWithState(payload))
    }
}

pub fn validate_id(vanity: &str) -> Result<(), ValidationError> {
    if !VANITY_RE.is_match(vanity) {
        return Err(ValidationError::new("alphanumerical"));
    }

    Ok(())
}

pub fn validate_password(
    password: &str,
    state: &crate::AppState,
) -> Result<(), ValidationError> {
    if let Some(score) = state.config.argon2.as_ref().and_then(|c| c.zxcvbn) {
        let entropy = zxcvbn::zxcvbn(password, &[]);
        if (entropy.score() as u8) < score {
            return Err(ValidationError::new("password"));
        }
    }

    Ok(())
}
