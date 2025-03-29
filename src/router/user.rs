//! Get and update user data.

use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use validator::{ValidationError, ValidationErrors};

use crate::crypto::check_key;
use crate::router::ServerError;
use crate::user::{Key, User};
use crate::AppState;
use crate::database::Database;

use super::login::check_password;
use super::Valid;

const ACTIVITY_STREAM: &str = "https://www.w3.org/ns/activitystreams";
const W3C_SECURITY: &str = "https://w3id.org/security/v1";

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum ActivityType {
    Add,
    Application,
    Article,
    Collection,
    Create,
    Image,
    Like,
    Link,
    Note,
    Object,
    OrderedCollection,
    Person,
    Place,
    Point,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    #[serde(rename = "@context")]
    context: Vec<String>,
    r#type: ActivityType,
    id: String,
    #[serde(rename = "preferredUsername")]
    username: String,
    name: String,
    url: String,
    summary: String,
    published: String,
    public_keys: Vec<Key>,
}

pub async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<Response>, ServerError> {
    let url = if let Ok(url) = url::Url::parse(&state.config.url) {
        format!(
            "{}://{}/users/{}",
            url.scheme(),
            url.host().map(|u| u.to_string()).unwrap_or_default(),
            user.id,
        )
    } else {
        user.id.clone()
    };

    Ok(Json(Response {
        context: vec![ACTIVITY_STREAM.to_owned(), W3C_SECURITY.to_owned()],
        r#type: ActivityType::Person,
        id: user.id.clone(),
        username: user.username.clone(),
        name: user.username,
        summary: String::default(),
        published: user.created_at.to_string(),
        public_keys: user.public_keys,
        url,
    }))
}

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
    public_keys: Option<TypedKey>,
    #[validate(email(message = "Email must be formated."))]
    email: Option<String>,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: Option<String>,
}

pub async fn patch(
    State(db): State<Database>,
    Extension(mut user): Extension<User>,
    Valid(body): Valid<Body>,
) -> Result<Json<Vec<String>>, ServerError> {
    let mut errors = ValidationErrors::new();

    if let Some(username) = body.username {
        user.username = username;
    }

    if let Some(_summary) = body.summary {
        unimplemented!()
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
                sqlx::query!(
                    r#"DELETE FROM keys WHERE id = $1 AND user_id = $2"#,
                    key,
                    user.id,
                )
                .execute(&db.postgres)
                .await?;
            },
        }
    }

    if let Some(email) = body.email {
        if let Some(password) = body.password {
            check_password(&password, &user.password)?;
            user.email = crate::crypto::email_encryption(email);
        } else {
            errors.add(
                "password",
                ValidationError::new("pwd").with_message("Missing 'password' field.".into()),
            );
        }
    }

    if !errors.is_empty() {
        return Err(ServerError::Validation(errors));
    }

    // Save keys.
    for key in pkeys.iter_mut() {
        let record = sqlx::query!(
            r#"INSERT INTO keys (user_id, key) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING RETURNING id"#,
            user.id,
            key.public_key_pem,
        )
        .fetch_optional(&db.postgres)
        .await?;

        if let Some(record) = record {
            key.id = record.id.to_string();
        }
    }

    // Save other user's data.
    sqlx::query!(
        r#"UPDATE users SET username = $1, email = $2 WHERE id = $3"#,
        user.username,
        user.email,
        user.id
    )
    .execute(&db.postgres)
    .await?;

    Ok(Json(pkeys.into_iter().map(|k| k.id).collect()))
}
