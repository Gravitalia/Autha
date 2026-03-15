//! RFC 7807 problem details for HTTP APIs.

use application::error::ApplicationError;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use domain::error::DomainError;
use serde::{Deserialize, Serialize};

/// RFC 7807 problem details.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// A URI reference that identifies the problem type.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// A short, human-readable summary of the problem.
    pub title: String,
    /// The HTTP status code.
    pub status: u16,
    /// A human-readable explanation specific to this occurrence.
    pub detail: String,
    /// A URI reference that identifies the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Additional fields for validation errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<FieldError>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
    pub code: String,
}

impl ProblemDetails {
    /// Create a new [`ProblemDetails`].
    pub fn new(
        status: StatusCode,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            problem_type: format!(
                "https://auth.gravitalia.com/errors/{}",
                status.as_u16()
            ),
            title: title.into(),
            status: status.as_u16(),
            detail: detail.into(),
            instance: None,
            errors: None,
        }
    }

    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = Some(errors);
        self
    }

    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    /// Convert ApplicationError to ProblemDetails with status code.
    pub fn from_application_error(
        err: ApplicationError,
    ) -> (StatusCode, Self) {
        match err {
            ApplicationError::Domain(domain_err) => {
                Self::from_domain_error(domain_err)
            },
            ApplicationError::UserNotFound => (
                StatusCode::NOT_FOUND,
                Self::new(
                    StatusCode::NOT_FOUND,
                    "User Not Found",
                    "The requested user could not be found in our records.",
                ),
            ),
            ApplicationError::AccountDeleted { date: _ } => (
                StatusCode::GONE,
                Self::new(
                    StatusCode::GONE,
                    "Account Deleted",
                    "This account was deleted.",
                ),
            ),
            ApplicationError::TooSmall { expected } => (
                StatusCode::BAD_REQUEST,
                Self::new(
                    StatusCode::BAD_REQUEST,
                    "Validation Failed",
                    format!(
                        "The provided argument is too short. Minimum length required is {}.",
                        expected
                    ),
                ),
            ),
            ApplicationError::Internal(err) => {
                tracing::error!(?err, "internal server error occurred");

                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Self::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        "An unexpected internal error occurred.",
                    ),
                )
            },
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "An unexpected error occurred. Please try again later.",
                ),
            ),
        }
    }

    /// Convert DomainError to ProblemDetails with status code.
    pub fn from_domain_error(err: DomainError) -> (StatusCode, Self) {
        match err {
            DomainError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                Self::new(
                    StatusCode::UNAUTHORIZED,
                    "Invalid credentials",
                    "The provided credentials are incorrect.",
                ),
            ),
            DomainError::TotpRequired => (
                StatusCode::BAD_REQUEST,
                Self::new(
                    StatusCode::BAD_REQUEST,
                    "TOTP required",
                    "A TOTP code is required for this account.",
                )
                .with_errors(vec![FieldError {
                    field: "totpCode".to_string(),
                    message: "TOTP code is required".to_string(),
                    code: "totp_required".to_string(),
                }]),
            ),
            DomainError::InvalidTotpCode => (
                StatusCode::UNAUTHORIZED,
                Self::new(
                    StatusCode::UNAUTHORIZED,
                    "Invalid TOTP code",
                    "The provided TOTP code is incorrect.",
                )
                .with_errors(vec![FieldError {
                    field: "totpCode".to_string(),
                    message: "TOTP code is invalid".to_string(),
                    code: "invalid_totp".to_string(),
                }]),
            ),
            DomainError::InvalidTotpSecret => (
                StatusCode::BAD_REQUEST,
                Self::new(
                    StatusCode::BAD_REQUEST,
                    "Invalid TOTP secret",
                    "The TOTP secret format is invalid.",
                ),
            ),
            DomainError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                Self::new(
                    StatusCode::UNAUTHORIZED,
                    "Token Expired",
                    "The provided token has expired.",
                ),
            ),
            DomainError::ValidationFailed { field, message } => (
                StatusCode::BAD_REQUEST,
                Self::new(
                    StatusCode::BAD_REQUEST,
                    "Validation Failed",
                    message.clone(),
                )
                .with_errors(vec![FieldError {
                    field: field.clone(),
                    message,
                    code: "validation_failed".to_string(),
                }]),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "An internal domain error occurred.",
                ),
            ),
        }
    }
}

/// Wrapper type for ApplicationError to implement IntoResponse.
pub struct HttpError(pub ApplicationError);

impl From<ApplicationError> for HttpError {
    fn from(err: ApplicationError) -> Self {
        Self(err)
    }
}

impl From<DomainError> for HttpError {
    fn from(err: DomainError) -> Self {
        Self(ApplicationError::Domain(err))
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let (status, problem) = ProblemDetails::from_application_error(self.0);
        (status, Json(problem)).into_response()
    }
}

pub trait IntoHttpResult<T> {
    fn into_http_result(self) -> Result<T, HttpError>;
}

impl<T> IntoHttpResult<T> for application::error::Result<T> {
    fn into_http_result(self) -> Result<T, HttpError> {
        self.map_err(HttpError::from)
    }
}
