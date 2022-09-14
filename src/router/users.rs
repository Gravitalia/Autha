use warp::reply::{WithStatus, Json};

use super::model;

pub async fn get(id: String) -> WithStatus<Json> {
    let user:model::User;

    if id == *"@me" {
        user = model::User {
            username: "d".to_string(),
            vanity: id,
            avatar: None,
            bio: None,
            verified: true,
            deleted: false,
            flags: 0,
        };
    } else {
        user = model::User {
            username: "xd".to_string(),
            vanity: id,
            avatar: Some("avatar".to_string()),
            bio: None,
            verified: true,
            deleted: false,
            flags: 0,
        };
    }

    warp::reply::with_status(warp::reply::json(&user), warp::http::StatusCode::OK)
}