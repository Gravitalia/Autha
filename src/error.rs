//! Error handler for autha.
use axum::extract::rejection::JsonRejection;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{postgres::PgDatabaseError, Error as SQLxError};
use thiserror::Error;
use validator::{ValidationError, ValidationErrors};

pub type Result<T> = std::result::Result<T, ServerError>;

/// Enum representing server-side errors.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("validation error occurred")]
    Validation(#[from] ValidationErrors),

    #[error("error parsing form data")]
    ParsingForm(Box<dyn std::error::Error>),

    #[error(transparent)]
    Axum(#[from] JsonRejection),

    #[error("SQL request failed: {0}")]
    Sql(#[from] SQLxError),

    #[error("invalid email")]
    WrongEmail,

    #[error("public key must be PCKS-1 or PCKS-8")]
    Key(#[from] crate::crypto::KeyError),

    #[error("internal server error, {details}")]
    Internal {
        details: String,
        source: Option<Box<dyn std::error::Error>>,
    },

    #[error("invalid 'Authorization' header")]
    Unauthorized,
}

impl From<ServerError> for ValidationErrors {
    fn from(error: ServerError) -> Self {
        let mut errors = ValidationErrors::new();

        match error {
            ServerError::WrongEmail => {
                errors.add(
                    "email",
                    ValidationError::new("email").with_message("Email must be formatted.".into()),
                );
            }
            ServerError::Key(_) => {
                errors.add(
                    "key",
                    ValidationError::new("publicKeys").with_message(
                        "Public key format must be PCKS1 (RSA) or PCKS8 (ECDSA).".into(),
                    ),
                );
            }
            _ => {}
        }

        errors
    }
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

    /// Update `title` field.
    pub fn title(mut self, title: &str) -> Self {
        self.title = title.into();
        self
    }

    /// Add detailed error.
    pub fn details(mut self, description: &str) -> Self {
        self.detail = description.into();
        self
    }

    /// Automatically add errors field.
    pub fn errors(mut self, errors: &ValidationErrors) -> Self {
        self.errors = Some(parse_validation_errors(errors));
        self
    }

    /// Transform [`ResponseError`] into axum [`Response`].
    pub fn into_response(self) -> std::result::Result<Response, axum::http::Error> {
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

#[derive(Debug, Serialize)]
struct FieldError {
    field: String,
    message: String,
}

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
        let response = ResponseError::default()
            .title("There were validation errors with your request.")
            .details(&self.to_string())
            .status(StatusCode::BAD_REQUEST);

        let response = match &self {
            ServerError::Validation(validation_errors) => response.errors(validation_errors),

            ServerError::ParsingForm(err) => response
                .title("Server error during data parsing.")
                .details(&err.to_string()),

            ServerError::Sql(err) => {
                let errors = match err {
                    sqlx::Error::Database(err) => {
                        let err = err.downcast_ref::<PgDatabaseError>();
                        let mut validation_errors = ValidationErrors::new();

                        match err.constraint() {
                            Some("users_pkey") => validation_errors.add(
                                "id",
                                ValidationError::new("sql")
                                    .with_message("ID is already in use.".into()),
                            ),
                            Some("users_email_key") => validation_errors.add(
                                "email",
                                ValidationError::new("sql")
                                    .with_message("Email is already in use.".into()),
                            ),
                            _ => tracing::error!(%err, "SQL query failed"),
                        }

                        validation_errors
                    }
                    _ => {
                        tracing::error!(%err, "SQL query failed");
                        ValidationErrors::new()
                    }
                };

                response.errors(&errors).details("")
            }

            ServerError::Unauthorized => response
                .title("Missing or invalid 'Authorization' header.")
                .status(StatusCode::UNAUTHORIZED),

            ServerError::Internal { details, source } => {
                tracing::error!(err = source, %details, "server returned 500 status");

                ResponseError::default()
            }

            _ => response,
        };

        response
            .errors(&self.into())
            .into_response()
            .unwrap_or_else(|_| internal_server_error())
    }
}

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
