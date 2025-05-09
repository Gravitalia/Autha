//! Route handler module with HTTP routes and validation.

use axum::extract::rejection::JsonRejection;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{postgres::PgDatabaseError, Error as SQLxError};
use thiserror::Error;
use validator::ValidationErrors;

/// Enum representing server-side errors.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Validation error occurred: {0:?}")]
    Validation(#[from] ValidationErrors),

    #[error("Error parsing form data: {0}")]
    ParsingForm(#[from] JsonRejection),

    #[error("SQL request failed: {0}")]
    Sql(#[from] SQLxError),

    #[error("invalid public key")]
    Key(crate::crypto::KeyError),

    #[error("internal server error")]
    Internal(String),

    #[error("invalid 'Authorization' header")]
    Unauthorized,
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
        if let Ok(body) = serde_json::to_string(&self) {
            Response::builder()
                .status(self.status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.into())
        } else {
            Ok(internal_server_error())
        }
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
            issues.iter().map(move |issue| FieldError {
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
                .unwrap_or_else(|_| internal_server_error()),
            ServerError::ParsingForm(err) => ResponseError::default()
                .title("Parsing error.")
                .details(&err.to_string())
                .status(StatusCode::BAD_REQUEST)
                .into_response()
                .unwrap_or_else(|_| internal_server_error()),
            ServerError::Sql(err) => ResponseError::default()
                .title("Invalid input.")
                .details(
                    err.as_database_error()
                        .and_then(|e| e.downcast_ref::<PgDatabaseError>().detail())
                        .unwrap_or(&err.to_string()),
                )
                .status(StatusCode::BAD_REQUEST)
                .into_response()
                .unwrap_or_else(|_| internal_server_error()),
            ServerError::Key(_) => ResponseError::default()
                .title("Invalid key format.")
                .details("Public key must be PCKS-1 or PCKS-8.")
                .status(StatusCode::BAD_REQUEST)
                .into_response()
                .unwrap_or_else(|_| internal_server_error()),
            ServerError::Internal(_err) => internal_server_error(),
            ServerError::Unauthorized => ResponseError::default()
                .title("Missing or invalid 'Authorization' header.")
                .status(StatusCode::UNAUTHORIZED)
                .into_response()
                .unwrap_or_else(|_| internal_server_error()),
        }
    }
}

/// Helper function to create a generic "Internal Server Error" response.
fn internal_server_error() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::json!({
                "type": null,
                "title": "Internal server error.",
                "status": StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                "detail": null,
                "instance": null,
                "errors": null,
            })
            .to_string()
            .into(),
        )
        .unwrap_or_else(|_| Response::new("Internal server error".into()))
}
