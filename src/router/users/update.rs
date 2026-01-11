//! Get and update user data.

use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};
use zeroize::Zeroizing;

use crate::crypto::check_key;
use crate::mail::Template::DataUpdate;
use crate::router::ValidWithState;
use crate::totp::generate_totp;
use crate::user::{Key, UserService};
use crate::{AppState, ServerError};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum TypedKey {
    One(String),
    Multiple(Vec<String>),
    Remove(i32),
}

#[derive(Debug, Validate, Serialize, Deserialize)]
#[validate(context = AppState)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    #[serde(alias = "preferredUsername")]
    #[serde(alias = "username")]
    #[validate(length(
        min = 2,
        max = 50,
        message = "Name must be 2 to 50 characters long."
    ))]
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
    #[validate(length(
        min = 8,
        message = "Password must contain at least 8 characters."
    ))]
    password: Option<Zeroizing<String>>,
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
    new_password: Option<Zeroizing<String>>,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(mut user): Extension<UserService>,
    ValidWithState(body): ValidWithState<Body>,
) -> Result<Json<Vec<String>>, ServerError> {
    let mut errors = ValidationErrors::new();

    if let Some(username) = body.username {
        user.data.username = username;
    }

    if let Some(summary) = body.summary {
        user.data.summary = Some(summary);
    }

    // TOTP modification.
    match (
        body.totp_secret.as_deref(),
        body.password.as_deref(),
        body.totp_code.as_deref(),
    ) {
        (Some(secret), Some(password), Some(code)) => {
            state
                .crypto
                .pwd
                .verify_password(password, &user.data.password)?;

            if generate_totp(secret, 30, 6)? == code {
                user.data.totp_secret =
                    Some(state.crypto.symmetric.encrypt_and_hex(secret)?);
            } else {
                errors.add(
                    "totp_code",
                    ValidationError::new("totp")
                        .with_message("TOTP code is wrong.".into()),
                );
            }
        },
        (Some(_), _, _)
            if body.password.is_none() || body.totp_code.is_none() =>
        {
            errors.add(
                "password",
                ValidationError::new("pwd").with_message(
                    "Missing 'password' or 'totp_code' field.".into(),
                ),
            );
        },
        (None, _, Some(_)) => {
            errors.add(
                "password",
                ValidationError::new("secret").with_message(
                    "Missing 'password' or 'totp_secret' field.".into(),
                ),
            );
        },
        _ => {},
    }

    // Public keys modification.
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
            },
            TypedKey::Multiple(keys) => {
                for key in keys {
                    check_key(&key).map_err(ServerError::Key)?;

                    pkeys.push(Key {
                        public_key_pem: key,
                        created_at: chrono::Utc::now().date_naive(),
                        ..Default::default()
                    })
                }
            },
            TypedKey::Remove(key) => {
                let _ = sqlx::query!(
                    r#"DELETE FROM keys WHERE id = $1 AND user_id = $2"#,
                    key,
                    user.data.id,
                )
                .execute(&state.db.postgres)
                .await
                .map_err(|_| {
                    errors.add(
                        "public_keys",
                        ValidationError::new("pkeys").with_message(
                            "Invalid key ID to be deleted.".into(),
                        ),
                    );
                });
            },
        }
    }

    // Email modification.
    if let Some((email, password)) =
        body.email.clone().zip(body.password.as_ref())
    {
        state
            .crypto
            .pwd
            .verify_password(password, &user.data.password)?;

        user.data.email_hash = state.crypto.hasher.digest(&email);
        user.data.email_cipher =
            state.crypto.symmetric.encrypt_and_hex(&email)?;
        state
            .mail
            .publish_event(DataUpdate, &email, &user.data)
            .await?;
    } else if body.email.is_some() {
        errors.add(
            "password",
            ValidationError::new("pwd")
                .with_message("Missing 'password' field.".into()),
        );
    }

    // Password modification.
    match (body.new_password, body.password.as_deref()) {
        (Some(new_pwd), Some(old_pwd)) => {
            state
                .crypto
                .pwd
                .verify_password(old_pwd, &user.data.password)?;

            user.data.password = state.crypto.pwd.hash_password(new_pwd)?;

            let user_email = state
                .crypto
                .symmetric
                .decrypt_from_hex(&user.data.email_cipher)?;

            state
                .mail
                .publish_event(DataUpdate, &user_email, &user.data)
                .await?;
        },
        (Some(_), None) => {
            errors.add(
                "password",
                ValidationError::new("pwd")
                    .with_message("Missing 'password' field.".into()),
            );
        },
        _ => {},
    }

    if !errors.is_empty() {
        return Err(ServerError::Validation(errors));
    }

    let mut tx = state.db.postgres.begin().await?;

    // Save keys.
    for key in pkeys.iter_mut() {
        let record = sqlx::query!(
            r#"INSERT INTO "keys" (user_id, key) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING RETURNING id"#,
            user.data.id,
            key.public_key_pem,
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(record) = record {
            key.id = record.id.to_string();
        }
    }

    // Save user data.
    user.update(tx).await?;

    Ok(Json(pkeys.into_iter().map(|k| k.id).collect()))
}
