use regex::Regex;
use warp::reply::{WithStatus, Json};
use sha256::digest;

pub async fn login(body: super::model::Create, finger: String) -> WithStatus<Json> {

}