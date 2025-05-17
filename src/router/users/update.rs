//! Get and update user data.

use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use validator::{ValidationError, ValidationErrors};

use crate::crypto::{check_key, Action};
use crate::router::login::check_password;
use crate::router::Valid;
use crate::totp::generate_totp;
use crate::user::{Key, User};
use crate::{AppState, ServerError};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum TypedKey {
    One(String),
    Multiple(Vec<String>),
    Remove(i32),
}

#[derive(Debug, validator::Validate, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    #[serde(alias = "preferredUsername")]
    #[serde(alias = "username")]
    #[validate(length(min = 2, max = 50, message = "Name must be 2 to 50 characters long."))]
    username: Option<String>,
    #[validate(length(
        min = 0,
        max = 255,
        message = "Biography must be 0 to 255 characters long."
    ))]
    summary: Option<String>,
    totp_secret: Option<String>,
    totp_code: Option<String>,
    public_keys: Option<TypedKey>,
    #[validate(email(message = "Email must be formated."))]
    email: Option<String>,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(mut user): Extension<User>,
    Valid(body): Valid<Body>,
) -> Result<Json<Vec<String>>, ServerError> {
    let mut errors = ValidationErrors::new();

    if let Some(username) = body.username {
        user.username = username;
    }

    if let Some(summary) = body.summary {
        user.summary = Some(summary);
    }

    if let Some(((secret, password), code)) = body
        .totp_secret
        .clone()
        .zip(body.password.clone())
        .zip(body.totp_code.clone())
    {
        check_password(&password, &user.password)?;
        if generate_totp(&secret, 30, 6).map_err(ServerError::Internal)? == code {
            user.totp_secret = Some(
                state
                    .crypto
                    .aes(Action::Encrypt, secret.as_bytes().to_vec())
                    .map_err(|err| ServerError::Internal(err.to_string()))?,
            );
        } else {
            errors.add(
                "totp_code",
                ValidationError::new("totp").with_message("TOTP code is wrong.".into()),
            );
        }
    } else if body.totp_secret.is_some() {
        errors.add(
            "password",
            ValidationError::new("pwd")
                .with_message("Missing 'password' or 'totp_code' field.".into()),
        );
    } else if body.totp_code.is_some() {
        errors.add(
            "password",
            ValidationError::new("secret")
                .with_message("Missing 'password' or 'totp_secret' field.".into()),
        );
    }

    let mut pkeys: Vec<Key> = Vec::new();
    if let Some(keys) = body.public_keys {
        match keys {
            TypedKey::One(key) => {
                check_key(&key).map_err(ServerError::Key)?;

                pkeys.push(Key {
                    public_key_pem: key,
                    created_at: chrono::Utc::now().date_naive(),
                    ..Default::default()
                })
            }
            TypedKey::Multiple(keys) => {
                for key in keys {
                    check_key(&key).map_err(ServerError::Key)?;

                    pkeys.push(Key {
                        public_key_pem: key,
                        created_at: chrono::Utc::now().date_naive(),
                        ..Default::default()
                    })
                }
            }
            TypedKey::Remove(key) => {
                let _ = sqlx::query!(
                    r#"DELETE FROM keys WHERE id = $1 AND user_id = $2"#,
                    key,
                    user.id,
                )
                .execute(&state.db.postgres)
                .await
                .map_err(|_| {
                    errors.add(
                        "public_keys",
                        ValidationError::new("pkeys")
                            .with_message("Invalid key ID to be deleted.".into()),
                    );
                });
            }
        }
    }

    if let Some((email, password)) = body.email.clone().zip(body.password) {
        check_password(&password, &user.password)?;
        user.email = state.crypto.format_preserving(&email);
    } else if body.email.is_some() {
        errors.add(
            "password",
            ValidationError::new("pwd").with_message("Missing 'password' field.".into()),
        );
    }

    if !errors.is_empty() {
        return Err(ServerError::Validation(errors));
    }

    // Save keys.
    for key in pkeys.iter_mut() {
        let record = sqlx::query!(
            r#"INSERT INTO "keys" (user_id, key) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING RETURNING id"#,
            user.id,
            key.public_key_pem,
        )
        .fetch_optional(&state.db.postgres)
        .await?;

        if let Some(record) = record {
            key.id = record.id.to_string();
        }
    }

    // Save other user's data.
    user.update(&state.db.postgres).await?;

    Ok(Json(pkeys.into_iter().map(|k| k.id).collect()))
}
