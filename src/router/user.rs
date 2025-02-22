//! Get and update user data.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::router::ServerError;
use crate::user::{Key, User};
use crate::AppState;

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
    Path(user_id): Path<String>,
) -> Result<Json<Response>, ServerError> {
    let user = User::default()
        .with_id(user_id)
        .get(&state.db.postgres)
        .await?;
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
    let public_keys = if let Some(pk_value) = user.public_keys {
        let mut keys: Vec<Key> = serde_json::from_str(&pk_value.to_string())
            .map_err(|_| ServerError::Internal("public keys seems corrupted".to_owned()))?;
        for key in &mut keys {
            if url != user.id {
                key.id = format!("{}#{}", url, key.id);
            }
        }
        keys
    } else {
        Vec::new()
    };

    Ok(Json(Response {
        context: vec![ACTIVITY_STREAM.to_owned(), W3C_SECURITY.to_owned()],
        r#type: ActivityType::Person,
        id: user.id.clone(),
        username: user.username.clone(),
        name: user.username,
        summary: String::default(),
        published: user.created_at.to_string(),
        public_keys,
        url,
    }))
}
