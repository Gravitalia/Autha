use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::crypto::Action;
use crate::error::Result;
use crate::router::create::Response;
use crate::user::User;
use crate::{AppState, ServerError};

use super::Valid;

fn at_least_one_contact(form: &Identifier) -> std::result::Result<(), ValidationError> {
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
        state
            .ldap
            .bind(&id, &body.password)
            .await
            .map_err(|err| ServerError::Internal {
                details: "invalid LDAP credentials".into(),
                source: Some(Box::new(err)),
            })?;

        User::builder()
            .with_id(id.to_lowercase())
            .with_password(&body.password)
            .create(&state.db.postgres)
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
        user,
        refresh_token,
        token,
    }))
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
        let config = config::Configuration::default().read().unwrap();
        let state = AppState {
            db: database::Database { postgres: pool },
            config: config.clone().into(),
            ldap: ldap::Ldap::default(),
            crypto: {
                let key = [0x42; 32];
                crypto::Cipher::key(hex::encode(key)).unwrap()
            },
            token: token::TokenManager::new(
                &config.name,
                &config.token.as_ref().unwrap().public_key_pem,
                &config.token.as_ref().unwrap().private_key_pem,
            )
            .unwrap(),
        };
        let app = app(state);

        let body = Body {
            identifier: Identifier {
                email: Some("test@gravitalia.com".into()),
                id: None,
            },
            password: "Password1234".into(),
            totp_code: None,
            _captcha: None,
        };
        let response =
            make_request(app.clone(), Method::POST, "/login", json!(body).to_string()).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = Body {
            identifier: Identifier {
                email: Some("admin@gravitalia.com".into()),
                id: None,
            },
            password: "StRong_Pa§$W0rD".into(),
            totp_code: None,
            _captcha: None,
        };
        let response = make_request(app, Method::POST, "/login", json!(body).to_string()).await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}
