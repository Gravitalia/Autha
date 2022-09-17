use warp::reply::{WithStatus, Json};
use super::model;
use crate::database::cassandra::query;

pub async fn get(id: String) -> WithStatus<Json> {
    let user:model::User = if id == *"@me" {
        println!("{:?}", query("SELECT vanity, username, verified, deleted, flags, avatar FROM accounts.users WHERE vanity = ?", vec![id]).await);

        model::User {
            username: "d".to_string(),
            vanity: "d".to_string(),
            avatar: None,
            bio: None,
            verified: true,
            deleted: false,
            flags: 0,
        }
    } else {
        model::User {
            username: "xd".to_string(),
            vanity: id,
            avatar: Some("avatar".to_string()),
            bio: None,
            verified: true,
            deleted: false,
            flags: 0,
        }
    };

    warp::reply::with_status(warp::reply::json(&user), warp::http::StatusCode::OK)
}