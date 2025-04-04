use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

use crate::{database::Database, totp::generate_totp, user::User};

use super::{ServerError, Valid};

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Body {
    #[validate(email(message = "Email must be formated."))]
    email: String,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: String,
    totp: Option<String>,
    _captcha: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    user: User,
    token: String,
}

#[inline(always)]
pub(super) fn check_password(pwd: &str, hash: &str) -> Result<(), ValidationErrors> {
    let hash = PasswordHash::new(hash).map_err(|err| {
        tracing::error!("Password decoding failed! {:?}", err);
        let error = ValidationError::new("decode").with_message("Dang... wtf!".into());
        let mut errors = ValidationErrors::new();
        errors.add("password", error);
        errors
    })?;
    Argon2::default()
        .verify_password(pwd.as_bytes(), &hash)
        .map_err(|_| {
            let error = ValidationError::new("invalid_password")
                .with_message("Password don't match.".into());
            let mut errors = ValidationErrors::new();
            errors.add("password", error);
            errors
        })
}

pub async fn login(
    State(db): State<Database>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>, ServerError> {
    let email = crate::crypto::email_encryption(body.email);
    let user = User::default().with_email(email).get(&db.postgres).await?;

    check_password(&body.password, &user.password)?;

    if let Some(ref secret) = user.totp_secret {
        let mut errors = ValidationErrors::new();

        if let Some(code) = body.totp {
            if generate_totp(secret, 30, 6).unwrap() != code {
                errors.add(
                    "totp",
                    ValidationError::new("invalid_totp").with_message("Invalid totp.".into()),
                );
            }
        } else {
            errors.add(
                "totp",
                ValidationError::new("invalid_totp").with_message("Missing 'totp' field.".into()),
            );
        }

        if !errors.is_empty() {
            return Err(ServerError::Validation(errors));
        }
    }

    let token = user.generate_token(&db.postgres).await?;

    Ok(Json(Response { user, token }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use axum::{
        body::Body as RequestBody,
        http::{self, Request, StatusCode},
    };
    use sqlx::{Pool, Postgres};
    use tower::ServiceExt;

    #[sqlx::test]
    async fn test_login_handler(pool: Pool<Postgres>) {
        let state = AppState {
            db: Database { postgres: pool },
            config: status::Configuration::default(),
        };
        let app = app(state);

        let body = Body {
            email: "test@gravitalia.com".into(),
            password: "Password1234".into(),
            totp: None,
            _captcha: None,
        };
        let body = serde_json::to_string(&body).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/login")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(RequestBody::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
