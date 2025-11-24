//! Get .

use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::ServerError;
use crate::user::{Key, User};

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

pub async fn handler(
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

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use sqlx::{Pool, Postgres};

    use super::*;
    use crate::*;

    const ID: &str = "admin";

    #[sqlx::test(fixtures("../../../fixtures/users.sql"))]
    async fn test_get_user_handler(pool: Pool<Postgres>) {
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
            mail: mail::MailManager::default(),
        };
        let app = app(state);

        let path = format!("/users/{}", ID);
        let response =
            make_request(app, Method::GET, &path, String::default()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Response = serde_json::from_slice(&body).unwrap();
        assert_eq!(body.id, ID);
    }
}
