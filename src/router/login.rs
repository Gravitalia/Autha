use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::crypto::Action;
use crate::error::Result;
use crate::router::create::{Response, TOKEN_TYPE};
use crate::user::User;
use crate::{AppState, ServerError};

use super::Valid;

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

#[derive(Debug, Serialize, Deserialize, Validate)]
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

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "at_least_one_contact"))]
struct Identifier {
    #[validate(email(message = "Email must be formatted."))]
    email: Option<String>,
    #[validate(
        length(min = 2, max = 15),
        custom(
            function = "crate::router::create::validate_id",
            message = "ID must be alphanumeric."
        )
    )]
    id: Option<String>,
}

pub async fn login(
    State(state): State<AppState>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>> {
    let user = if let Some(email) = body.identifier.email {
        let email = state
            .crypto
            .aes_no_iv(Action::Encrypt, email.into())
            .await
            .map_err(|err| ServerError::Internal {
                details: "email cannot be encrypted".into(),
                source: Some(Box::new(err)),
            })?;
        let user = User::builder()
            .with_email(email)
            .get(&state.db.postgres)
            .await
            .map_err(|_| ServerError::WrongEmail)?;

        state
            .crypto
            .check_password(&body.password, &user.password)
            .await?;
        state
            .crypto
            .check_totp(body.totp_code, &user.totp_secret)
            .await?;
        user
    } else if let Some(id) = body.identifier.id {
        state.ldap.bind(&id, &body.password).await.map_err(|err| {
            ServerError::Internal {
                details: "invalid LDAP credentials".into(),
                source: Some(Box::new(err)),
            }
        })?;

        User::builder()
            .with_id(id.to_lowercase())
            .with_password(&body.password)
            .create(&state.crypto, &state.db.postgres)
            .await?
        /*.with_id(id)
        .with_password(state.crypto.hash_password(&body.password)?)
        .create(&state.db.postgres)
        .await?
        .get(&state.db.postgres)
        .await?*/
    } else {
        return Err(ServerError::WrongEmail);
    };

    let refresh_token = user.generate_token(&state.db.postgres).await?;
    let token = state.token.create(&user.id)?;
    Ok(Json(Response {
        token_type: TOKEN_TYPE.to_owned(),
        token,
        refresh_token,
        expires_in: crate::token::EXPIRATION_TIME,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use serde_json::json;
    use sqlx::{Pool, Postgres};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[sqlx::test(fixtures("../../fixtures/users.sql"))]
    async fn test_login_handler(pool: Pool<Postgres>) {
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
            .as_secs() as u64;
        assert!(claims.exp > time);
    }
}
