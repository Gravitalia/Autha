use warp::reply::{WithStatus, Json};

pub async fn get(id: str) -> WithStatus<Json> {
    if id == "@me" {

    }
}