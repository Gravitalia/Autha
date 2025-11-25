use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::AppState;
use crate::error::Result;
use crate::mail::Template::Welcome;
use crate::router::ValidWithState;
use crate::user::User;

pub const TOKEN_TYPE: &str = "Bearer";

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(context = AppState)]
pub struct Body {
    #[validate(
        length(min = 2, max = 15),
        custom(
            function = "crate::router::validate_id",
            message = "Vanity must be alphanumeric."
        )
    )]
    pub id: String,
    #[validate(email(message = "Email must be formatted."))]
    email: String,
    #[validate(
        length(
            min = 8,
            max = 255,
            message = "Password must contain at least 8 characters."
        ),
        custom(
            function = "crate::router::validate_password",
            message = "Password is too weak.",
            use_context
        )
    )]
    password: String,
    #[validate(length(
        equal = 2,
        message = "Locale must be ISO 3166-1 alpha-2."
    ))]
    locale: Option<String>,
    pub invite: Option<String>,
    _captcha: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub token_type: String,
    pub token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Handler to create user.
pub async fn handler(
    State(state): State<AppState>,
    ValidWithState(body): ValidWithState<Body>,
) -> Result<(StatusCode, Json<Response>)> {
    let user = User::builder()
        .with_id(body.id.to_lowercase())
        .with_locale(body.locale)
        .with_email(&body.email)
        .with_password(&body.password)
        .create(&state.crypto, &state.db.postgres)
        .await?;

    state.mail.publish_event(Welcome, body.email).await?;

    let refresh_token = user.generate_token(&state.db.postgres).await?;
    let token = state.token.create(&user.id)?;

    if let Err(err) = state.ldap.add(&state.crypto, &user).await {
        tracing::error!(
            user_id = user.id,
            error = err.to_string(),
            "user not created on ldap"
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

    #[sqlx::test]
    async fn test_create_handler(pool: Pool<Postgres>) {
        let state = router::state(pool);
        let app = app(state.clone());

        let req_body = router::create::Body {
            id: "user".into(),
            email: "test@gravitalia.com".into(),
            password: "P$soW%920$n&".into(),
            locale: None,
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
        let state = router::state(pool);
        let app = app(state.clone());

        let req_body = router::create::Body {
            id: "user2".into(),
            email: "test2@gravitalia.com".into(),
            password: "Pas$word1111".into(),
            locale: None,
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
