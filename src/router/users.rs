use warp::reply::{WithStatus, Json};
use super::model;
use crate::database::cassandra::query;

pub async fn get(id: String) -> WithStatus<Json> {
    let user = query("SELECT username, avatar, bio, verified, deleted, flags FROM accounts.users WHERE vanity = ?", vec![id.clone()]).await.rows.unwrap();

    if user.is_empty() {
        warp::reply::with_status(warp::reply::json(
            &model::Error {
                error: true,
                message: "Unknown user".to_string()
            }
        ), warp::http::StatusCode::NOT_FOUND)
    } else {
        warp::reply::with_status(warp::reply::json(
            &model::User {
                username: user[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string(),
                vanity: id,
                avatar: if user[0].columns[1].is_none() { None } else { Some(user[0].columns[1].as_ref().unwrap().as_text().unwrap().to_string()) },
                bio: if user[0].columns[2].is_none() { None } else { Some(user[0].columns[2].as_ref().unwrap().as_text().unwrap().to_string()) },
                verified: user[0].columns[3].as_ref().unwrap().as_boolean().unwrap(),
                deleted: user[0].columns[4].as_ref().unwrap().as_boolean().unwrap(),
                flags: user[0].columns[5].as_ref().unwrap().as_int().unwrap() as u32,
            }
        ), warp::http::StatusCode::OK)
    }
}