use std::usize;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use axum::{extract::State, http::StatusCode, Json};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

use super::{ServerError, Valid};
use crate::user::User;
use crate::AppState;

fn validate_id(vanity: &str) -> Result<(), ValidationError> {
    if !Regex::new(r"[A-Za-z0-9\-\.\_\~\!\$\&\'\(\)\*\+\,\;\=](?:[A-Za-z0-9\-\.\_\~\!\$\&\'\(\)\*\+\,\;\=]|(?:%[0-9A-Fa-f]{2}))$")
            .map_err(|_| ValidationError::new("wtf_regex"))?
            .is_match(vanity) {
        return Err(ValidationError::new("alphanumerical"));
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Body {
    #[validate(
        length(min = 2, max = 15),
        custom(function = "validate_id", message = "Vanity must be alphanumeric.")
    )]
    id: String,
    #[validate(email(message = "Email must be formated."))]
    email: String,
    #[validate(length(
        min = 8,
        max = 255,
        message = "Password must contain at least 8 characters."
    ))]
    password: String,
    #[validate(length(min = 4, max = 14, message = "Invalid invite code."))]
    invite: Option<String>,
    _captcha: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    user: User,
    token: String,
}

fn invalid_code() -> ValidationErrors {
    let mut errors = ValidationErrors::new();
    errors.add(
        "invite",
        ValidationError::new("invite").with_message("Invalid invite code.".into()),
    );
    errors
}

pub async fn create(
    State(state): State<AppState>,
    Valid(body): Valid<Body>,
) -> Result<(StatusCode, Json<Response>), ServerError> {
    // If invite is required, check it.
    if state.config.invite_only {
        if let Some(ref invite) = body.invite {
            let is_used = sqlx::query!(
                r#"SELECT used_at IS NOT NULL AS is_used FROM "invite_codes" WHERE code = $1"#,
                invite
            )
            .fetch_one(&state.db.postgres)
            .await
            .map_err(|_| invalid_code())?
            .is_used;

            if is_used.unwrap_or(false) {
                return Err(ServerError::Validation(invalid_code()));
            }
        } else {
            return Err(ServerError::Validation(invalid_code()));
        }
    }

    // Creation logic.
    let email = crate::crypto::email_encryption(body.email);
    let password = {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(Params::DEFAULT_M_COST * 4, 6, Params::DEFAULT_P_COST, None)
            .map_err(|err| ServerError::Internal(err.to_string()))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let password_hash = argon2
            .hash_password(body.password.as_bytes(), &salt)
            .map_err(|err| ServerError::Internal(err.to_string()))?
            .to_string();
        let hash = PasswordHash::new(&password_hash)
            .map_err(|err| ServerError::Internal(err.to_string()))?;

        hash.to_string()
    };

    sqlx::query!(
        r#"INSERT INTO "users" (id, username, email, password) VALUES ($1, $2, $3, $4)"#,
        body.id.to_lowercase(),
        body.id,
        email,
        password
    )
    .execute(&state.db.postgres)
    .await?;

    let user = User::default()
        .with_id(body.id.to_lowercase())
        .get(&state.db.postgres)
        .await?;
    let token = user.generate_token(&state.db.postgres).await?;

    // Set invite code as used.
    if state.config.invite_only {
        sqlx::query!(
            r#"UPDATE "invite_codes" SET used_by = $1, used_at = NOW() WHERE code = $2"#,
            user.id,
            body.invite.unwrap_or_default(),
        )
        .execute(&state.db.postgres)
        .await?;
    }

    Ok((StatusCode::CREATED, Json(Response { user, token })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use axum::{
        body::Body as RequestBody,
        http::{self, Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sqlx::{Pool, Postgres};
    use tower::ServiceExt;

    #[sqlx::test]
    async fn test_create_handler(pool: Pool<Postgres>) {
        let state = AppState {
            db: database::Database { postgres: pool },
            config: status::Configuration::default(),
        };
        let app = app(state);

        let body = router::create::Body {
            id: "user".into(),
            email: "test@gravitalia.com".into(),
            password: "Password1234".into(),
            _captcha: None,
            invite: None,
        };
        let body = serde_json::to_string(&body).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/create")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(RequestBody::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Response = serde_json::from_slice(&body).unwrap();
        assert!(body.token.is_ascii());
        assert_eq!(body.user.id, "user");
    }
}
