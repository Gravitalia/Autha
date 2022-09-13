use warp::reply::{WithStatus, Json};

pub async fn get(id: String) -> WithStatus<Json> {
    if id == "@me".to_string() {
        warp::reply::with_status(warp::reply::json(
            &super::model::CreateResponse{
                token: id
            }
        ),
        warp::http::StatusCode::OK)
    } else {
        warp::reply::with_status(warp::reply::json(
            &super::model::CreateResponse{
                token: id
            }
        ),
        warp::http::StatusCode::OK)
    }
}