//! Custom Axum extractors for validation and authentication.

use axum::Json;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use validator::Validate;

use super::errors::{FieldError, ProblemDetails};

/// Automatically validates request bodies using the `validator` crate.
pub struct Valid<T>(pub T);

impl<T, S> FromRequest<S> for Valid<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = ValidationErrorResponse;

    async fn from_request(
        req: Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Json(value) =
            Json::<T>::from_request(req, state).await.map_err(|err| {
                ValidationErrorResponse(ProblemDetails::new(
                    StatusCode::BAD_REQUEST,
                    "Invalid JSON",
                    format!("Failed to parse JSON: {}", err),
                ))
            })?;

        value.validate().map_err(|errors| {
            let field_errors: Vec<FieldError> = errors
                .field_errors()
                .iter()
                .flat_map(|(field, errs)| {
                    errs.iter().map(move |err| FieldError {
                        field: field.to_string(),
                        message: err
                            .message
                            .as_ref()
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| {
                                "Validation failed".to_string()
                            }),
                        code: err.code.to_string(),
                    })
                })
                .collect();

            ValidationErrorResponse(
                ProblemDetails::new(
                    StatusCode::BAD_REQUEST,
                    "Validation Failed",
                    "One or more fields failed validation.",
                )
                .with_errors(field_errors),
            )
        })?;

        Ok(Valid(value))
    }
}

pub struct ValidationErrorResponse(ProblemDetails);

impl IntoResponse for ValidationErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self.0)).into_response()
    }
}

/// Bearer token extractor.
pub struct BearerToken(pub String);

impl<S> FromRequest<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(
        req: Request,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ProblemDetails::new(
                        StatusCode::UNAUTHORIZED,
                        "Missing Authorization Header",
                        "Authorization header is required.",
                    )),
                )
                    .into_response()
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ProblemDetails::new(
                        StatusCode::UNAUTHORIZED,
                        "Invalid Authorization Header",
                        "Authorization header must be in the format: Bearer <token>",
                    )),
                )
                    .into_response()
            })?
            .to_string();

        Ok(BearerToken(token))
    }
}
