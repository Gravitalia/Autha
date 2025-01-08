//! Route handler module with HTTP routes and validation.

pub mod status;
pub mod create;

use axum::{
    extract::{rejection::JsonRejection, FromRequest, Request},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use validator::{Validate, ValidationErrors};

/// A wrapper struct for validating form data.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedForm<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedForm<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = ServerError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(payload) = Json::<T>::from_request(req, state).await?;
        payload.validate()?;
        Ok(ValidatedForm(payload))
    }
}

/// Enum representing server-side errors.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Validation error occurred: {0:?}")]
    Validation(#[from] ValidationErrors),

    #[error("Error parsing form data: {0}")]
    ParsingForm(#[from] JsonRejection),
}

/// Structure for detailed error responses.
#[derive(Debug, Serialize)]
struct DetailedError {
    r#type: Option<String>,
    title: String,
    status: u16,
    detail: String,
    instance: Option<String>,
    validation_errors: Option<Vec<FieldError>>,
}

/// Represents a specific field error.
#[derive(Debug, Serialize)]
struct FieldError {
    field: String,
    message: String,
}

/// Converts validation errors into a vector of `FieldError`.
fn parse_validation_errors(errors: &ValidationErrors) -> Vec<FieldError> {
    errors
        .field_errors()
        .iter()
        .flat_map(|(field, issues)| {
            issues.iter().map(|issue| FieldError {
                field: field.to_string(),
                message: issue.to_string(),
            })
        })
        .collect()
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, error) = match &self {
            ServerError::Validation(validation_errors) => {
                let field_errors = parse_validation_errors(validation_errors);
                let error = DetailedError {
                    r#type: None,
                    title: "Invalid input.".to_owned(),
                    status: StatusCode::BAD_REQUEST.as_u16(),
                    detail: "There were validation errors with your request.".to_string(),
                    instance: None,
                    validation_errors: Some(field_errors),
                };
                (StatusCode::BAD_REQUEST, error)
            }
            ServerError::ParsingForm(_) => {
                let error = DetailedError {
                    r#type: None,
                    title: "Parsing Error".to_string(),
                    status: StatusCode::BAD_REQUEST.as_u16(),
                    detail: "The provided form data could not be parsed.".to_string(),
                    instance: None,
                    validation_errors: None,
                };
                (StatusCode::BAD_REQUEST, error)
            }
        };

        let body = serde_json::to_string(&error).unwrap_or_else(|_| {
            serde_json::json!({
                "title": "Internal Server Error",
                "status": StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .to_string()
        });

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap()
    }
}
