use axum::{Json, extract::State, http::StatusCode};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

use crate::AppState;
use crate::ServerError;
use crate::crypto::Action;
use crate::error::Result;
use crate::user::User;

use std::sync::LazyLock;

use super::Valid;

static VANITY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]+$").unwrap());
pub const TOKEN_TYPE: &str = "Bearer";

pub fn validate_id(vanity: &str) -> std::result::Result<(), ValidationError> {
    if !VANITY_RE.is_match(vanity) {
        return Err(ValidationError::new("alphanumerical"));
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Body {
    #[validate(
        length(min = 2, max = 15),
        custom(
            function = "validate_id",
            message = "Vanity must be alphanumeric."
        )
    )]
    pub id: String,
    #[validate(email(message = "Email must be formatted."))]
    email: String,
    #[validate(length(
        min = 8,
        max = 255,
        message = "Password must contain at least 8 characters."
    ))]
    password: String,
    invite: Option<String>,
    _captcha: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub token_type: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

fn invalid_code() -> ValidationErrors {
    let mut errors = ValidationErrors::new();
    errors.add(
        "invite",
        ValidationError::new("invite")
            .with_message("Invalid invite code.".into()),
    );
    errors
}

fn password_too_weak() -> ValidationErrors {
    let mut errors = ValidationErrors::new();
    errors.add(
        "password",
        ValidationError::new("password").with_message(
            "Password must contain at least 8 characters.".into(),
        ),
    );
    errors
}

/// Middleware to handle invite codes.
pub async fn middleware(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response> {
    if state.config.invite_only {
        let (parts, body) = req.into_parts();
        let body_bytes = axum::body::to_bytes(body, 30_000)
            .await
            .map_err(|err| ServerError::ParsingForm(Box::new(err)))?;
        let body = serde_json::from_slice::<Body>(&body_bytes)
            .map_err(|err| ServerError::ParsingForm(Box::new(err)))?;

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

        let req = axum::extract::Request::from_parts(
            parts,
            axum::body::Body::from(body_bytes),
        );
        let response = next.run(req).await;

        if response.status().is_success() {
            sqlx::query!(
                r#"UPDATE "invite_codes" SET used_by = $1, used_at = NOW() WHERE code = $2"#,
                body.id,
                body.invite.unwrap_or_default(),
            )
            .execute(&state.db.postgres)
            .await?;
        }

        Ok(response)
    } else {
        Ok(next.run(req).await)
    }
}

pub async fn create(
    State(state): State<AppState>,
    Valid(body): Valid<Body>,
) -> Result<(StatusCode, Json<Response>)> {
    if let Some(score) = state.config.argon2.as_ref().and_then(|c| c.zxcvbn) {
        let entropy = zxcvbn::zxcvbn(&body.password, &[&body.email, &body.id]);
        if (entropy.score() as u8) < score {
            return Err(ServerError::Validation(password_too_weak()));
        }
    }

    let email = state
        .crypto
        .aes_no_iv(Action::Encrypt, body.email.into())
        .await
        .map_err(|err| ServerError::Internal {
            details: "email cannot be encrypted".into(),
            source: Some(Box::new(err)),
        })?;

    let user = User::builder()
        .with_id(body.id.to_lowercase())
        .with_email(email)
        .with_password(&body.password)
        .create(&state.crypto, &state.db.postgres)
        .await?;

    let refresh_token = user.generate_token(&state.db.postgres).await?;
    let token = state.token.create(&user.id)?;

    if let Err(err) = state.ldap.add(&user).await {
        tracing::error!(
            user_id = user.id,
            error = err.to_string(),
            "user not created on LDAP"
        );
    }

    Ok((
        StatusCode::CREATED,
        Json(Response {
            token_type: TOKEN_TYPE.to_owned(),
            token,
            refresh_token,
            expires_in: crate::token::EXPIRATION_TIME,
        }),
    ))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::*;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use serde_json::json;
    use sqlx::{Pool, Postgres};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn state(pool: Pool<Postgres>) -> AppState {
        let config = config::Configuration::default().read().unwrap();
        let state = AppState {
            db: database::Database { postgres: pool },
            config: config.clone().into(),
            ldap: ldap::Ldap::default(),
            crypto: {
                let key = [0x42; 32];
                crypto::Cipher::from_key(hex::encode(key)).unwrap()
            },
            token: token::TokenManager::new(
                &config.url,
                config.token.clone().unwrap().key_id,
                &config.token.as_ref().unwrap().public_key_pem,
                &config.token.as_ref().unwrap().private_key_pem,
            )
            .unwrap(),
        };
        state
    }

    #[sqlx::test]
    async fn test_create_handler(pool: Pool<Postgres>) {
        let state = state(pool);
        let app = app(state.clone());

        let req_body = router::create::Body {
            id: "user".into(),
            email: "test@gravitalia.com".into(),
            password: "P$soW%920$n&".into(),
            _captcha: None,
            invite: None,
        };
        let response = make_request(
            app,
            Method::POST,
            "/create",
            json!(req_body).to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Response = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.token_type, TOKEN_TYPE);
        assert_eq!(body.expires_in, crate::token::EXPIRATION_TIME);
        assert!(body.token.is_ascii());
        assert!(body.refresh_token.is_ascii());

        let claims = state.token.decode(&body.token).unwrap();
        assert_eq!(claims.sub, req_body.id);
        assert_eq!(claims.iss, state.config.url);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;
        assert!(claims.exp > time);
    }

    #[sqlx::test]
    async fn test_create_with_weak_password(pool: Pool<Postgres>) {
        let state = state(pool);
        let app = app(state.clone());

        let req_body = router::create::Body {
            id: "user2".into(),
            email: "test2@gravitalia.com".into(),
            password: "Pas$word1111".into(),
            _captcha: None,
            invite: None,
        };
        let response = make_request(
            app,
            Method::POST,
            "/create",
            json!(req_body).to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
