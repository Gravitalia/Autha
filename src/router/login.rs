use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

use crate::ServerError;
use crate::{database::Database, totp::generate_totp, user::User};

use super::Valid;

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Body {
    #[validate(email(message = "Email must be formated."))]
    email: String,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: String,
    #[serde(rename = "totpCode")]
    totp_code: Option<String>,
    _captcha: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    user: User,
    token: String,
}

#[inline]
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

#[inline]
pub(super) fn check_totp(code: Option<String>, secret: Option<String>) -> Result<(), ServerError> {
    if let Some(ref secret) = secret {
        let mut errors = ValidationErrors::new();

        if let Some(code) = code {
            if generate_totp(secret, 30, 6).map_err(ServerError::Internal)? != code {
                errors.add(
                    "totpCode",
                    ValidationError::new("invalid_totp").with_message("TOTP code is wrong.".into()),
                );
            }
        } else {
            errors.add(
                "totpCode",
                ValidationError::new("invalid_totp")
                    .with_message("Missing 'totpCode' field.".into()),
            );
        }

        if !errors.is_empty() {
            return Err(ServerError::Validation(errors));
        }
    }

    Ok(())
}

pub async fn login(
    State(db): State<Database>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>, ServerError> {
    let email = crate::crypto::email_encryption(body.email);
    let user = User::default().with_email(email).get(&db.postgres).await?;

    check_password(&body.password, &user.password)?;
    check_totp(body.totp_code, user.totp_secret.clone())?;

    let token = user.generate_token(&db.postgres).await?;

    Ok(Json(Response { user, token }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use axum::http::StatusCode;
    use serde_json::json;
    use sqlx::{Pool, Postgres};

    #[sqlx::test(fixtures("../../fixtures/users.sql"))]
    async fn test_login_handler(pool: Pool<Postgres>) {
        let state = AppState {
            db: Database { postgres: pool },
            config: status::Configuration::default(),
            ldap: ldap::Ldap::default(),
        };
        let app = app(state);

        let body = Body {
            email: "test@gravitalia.com".into(),
            password: "Password1234".into(),
            totp_code: None,
            _captcha: None,
        };
        let response =
            make_request(app.clone(), Method::POST, "/login", json!(body).to_string()).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = Body {
            email: "admin@gravitalia.com".into(),
            password: "StRong_Pa§$W0rD".into(),
            totp_code: None,
            _captcha: None,
        };
        let response = make_request(app, Method::POST, "/login", json!(body).to_string()).await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}
