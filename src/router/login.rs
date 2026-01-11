use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Result;
use crate::router::Valid;
use crate::router::create::{Response, TOKEN_TYPE};
use crate::user::{UserBuilder, UserService};
use crate::{AppState, ServerError};

fn at_least_one_contact(
    form: &Identifier,
) -> std::result::Result<(), ValidationError> {
    if form.email.is_none() && form.id.is_none() {
        let mut error = ValidationError::new("missing_identifier");
        error.message = Some("Email must be formatted.".into());
        return Err(error);
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Validate, Zeroize, ZeroizeOnDrop)]
pub struct Body {
    #[serde(flatten)]
    #[validate(nested)]
    identifier: Identifier,
    #[validate(length(
        min = 8,
        max = 64,
        message = "Password must contain at least 8 characters."
    ))]
    password: String,
    #[serde(rename = "totpCode")]
    totp_code: Option<String>,
    _captcha: Option<String>,
}

#[derive(Serialize, Deserialize, Validate, Zeroize, ZeroizeOnDrop)]
#[validate(schema(function = "at_least_one_contact"))]
struct Identifier {
    #[validate(email(message = "Email must be formatted."))]
    email: Option<String>,
    #[validate(
        length(min = 2, max = 15),
        custom(
            function = "crate::router::validate_id",
            message = "ID must be alphanumeric."
        )
    )]
    id: Option<String>,
}

/// Handler to login user.
pub async fn handler(
    State(state): State<AppState>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>> {
    let user = if let Some(ref email) = body.identifier.email {
        default_login(&state, email, &body).await?
    } else if let Some(ref id) = body.identifier.id {
        ldap_login(&state, id, &body).await?
    } else {
        return Err(ServerError::WrongEmail);
    };

    let refresh_token = user.generate_token().await?;
    let token = state.token.create(&user.data.id)?;
    Ok(Json(Response {
        token_type: TOKEN_TYPE.to_owned(),
        token,
        refresh_token,
        expires_in: crate::token::EXPIRATION_TIME,
    }))
}

async fn default_login(
    state: &AppState,
    email: &str,
    body: &Body,
) -> Result<UserService> {
    let email_hash = state.crypto.hasher.digest(email);
    let user = UserBuilder::new()
        .email(email_hash)
        .build(state.db.postgres.clone(), Arc::clone(&state.crypto))
        .find_by_email()
        .await
        .map_err(|_| ServerError::WrongEmail)?;

    state
        .crypto
        .pwd
        .verify_password(&body.password, &user.data.password)?;
    state.crypto.symmetric.check_totp(
        body.totp_code.as_deref(),
        user.data.totp_secret.as_deref(),
    )?;
    Ok(user)
}

async fn ldap_login(
    state: &AppState,
    id: &str,
    body: &Body,
) -> Result<UserService> {
    let Some(ref ldap) = state.ldap else {
        return Err(ServerError::Unauthorized);
    };

    ldap.authenticate(id, &body.password).await?;

    UserBuilder::new()
        .id(id.to_lowercase())
        .password(&body.password)
        .build(state.db.postgres.clone(), Arc::clone(&state.crypto))
        .create_user()
        .await
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use serde_json::json;
    use sqlx::{Pool, Postgres};

    use super::*;
    use crate::*;

    #[sqlx::test(fixtures("../../fixtures/users.sql"))]
    async fn test_login_handler(pool: Pool<Postgres>) {
        let state = router::state(pool);
        let app = app(state.clone());

        let body = Body {
            identifier: Identifier {
                email: Some("test@gravitalia.com".into()),
                id: None,
            },
            password: "Password1234".into(),
            totp_code: None,
            _captcha: None,
        };
        let response = make_request(
            None,
            app.clone(),
            Method::POST,
            "/login",
            json!(body).to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let req_body = Body {
            identifier: Identifier {
                email: Some("admin@gravitalia.com".into()),
                id: None,
            },
            password: "StRong_Pa§$W0rD".into(),
            totp_code: None,
            _captcha: None,
        };
        let response = make_request(
            None,
            app,
            Method::POST,
            "/login",
            json!(req_body).to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Response = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.token_type, TOKEN_TYPE);
        assert_eq!(body.expires_in, crate::token::EXPIRATION_TIME);
        assert!(body.token.is_ascii());
        assert!(body.refresh_token.is_ascii());

        let claims = state.token.decode(&body.token).unwrap();
        assert_eq!(claims.iss, state.config.url);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(claims.exp > time);
    }

    #[sqlx::test]
    async fn test_login_injection(pool: Pool<Postgres>) {
        const INJECTION: &str = "\"\0\0\0\"\u{FFFF}\"@gravitalia.com";
        let state = router::state(pool);
        let app = app(state);

        let body = Body {
            identifier: Identifier {
                email: Some(INJECTION.into()),
                id: None,
            },
            password: "StRong_Pa§$W0rD".into(),
            totp_code: None,
            _captcha: None,
        };
        let response = make_request(
            None,
            app.clone(),
            Method::POST,
            "/login",
            json!(body).to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
