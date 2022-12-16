use crate::database::cassandra::query;
use warp::reply::{WithStatus, Json};

pub async fn post(body: super::model::OAuth, vanity: String) -> WithStatus<Json> {
    // If empty, tries to find a valid code
    if body.response_type.is_empty() {
        let res = query("SELECT id FROM accounts.oauth WHERE user_id = ?", vec![vanity]).await.rows.unwrap();
        if res.is_empty() {
            return super::err("No code".to_string());
        } else {
            return warp::reply::with_status(warp::reply::json(
                &super::model::Error{
                    error: false,
                    message: res[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string(),
                }
            ),
            warp::http::StatusCode::OK);
        }
    } else {
        // Create code here
    }

    super::err("In dev".to_string())
}