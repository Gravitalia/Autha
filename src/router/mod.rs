//! Route handler module with HTTP routes and validation.

pub mod create;
pub mod status;

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
pub struct ResponseError {
    r#type: Option<String>,
    title: String,
    status: u16,
    detail: String,
    instance: Option<String>,
    errors: Option<Vec<FieldError>>,
}

impl ResponseError {
    /// Update error status code.
    pub fn status(mut self, code: StatusCode) -> Self {
        self.status = code.as_u16();
        self
    }

    pub fn title(mut self, title: &str) -> Self {
        self.title = title.into();
        self
    }

    pub fn details(mut self, description: &str) -> Self {
        self.detail = description.into();
        self
    }

    /// Automatically add errors field.
    pub fn errors(mut self, errors: &ValidationErrors) -> Self {
        self.errors = Some(parse_validation_errors(errors));
        self
    }

    pub fn into_response(self) -> Result<Response, axum::http::Error> {
        let body = serde_json::to_string(&self).unwrap_or_else(|_| {
            serde_json::json!({
                "title": "Internal server error.",
                "status": StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .to_string()
        });

        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
    }
}

impl Default for ResponseError {
    fn default() -> Self {
        Self {
            r#type: None,
            title: "Internal server error.".to_owned(),
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            detail: String::default(),
            instance: None,
            errors: None,
        }
    }
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
        match &self {
            ServerError::Validation(validation_errors) => ResponseError::default()
                .title("Invalid input.")
                .details("There were validation errors with your request.")
                .errors(validation_errors)
                .status(StatusCode::BAD_REQUEST)
                .into_response()
                .unwrap(),
            ServerError::ParsingForm(err) => {
                ResponseError::default()
                    .title("Parsing error.")
                    .details(&err.to_string())
                    .status(StatusCode::BAD_REQUEST)
                    .into_response()
                    .unwrap()
            }
        }
    }
}
