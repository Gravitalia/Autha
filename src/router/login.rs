use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

use crate::{database::Database, user::User};

use super::{ServerError, Valid};

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Body {
    #[validate(email(message = "Email must be formated."))]
    email: String,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: String,
    _captcha: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    user: User,
    token: String,
}

pub async fn login(
    State(db): State<Database>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>, ServerError> {
    let email = crate::crypto::email_encryption(body.email);
    let user = User::default().with_email(email).get(&db.postgres).await?;
    let password = PasswordHash::new(&user.password).unwrap();

    Argon2::default()
        .verify_password(body.password.as_bytes(), &password)
        .map_err(|_| {
            let error = ValidationError::new("invalid_password")
                .with_message("Password don't match.".into());
            let mut errors = ValidationErrors::new();
            errors.add("password", error);
            errors
        })?;

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
