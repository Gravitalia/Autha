use warp::reply::{WithStatus, Json};
use super::model;
use crate::database::cassandra::query;

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into().unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

fn vec_to_bool(vec: &Vec<u8>) -> bool {
    if vec[0] == 0 {
        false
    } else {
        true
    }
}

fn vec_to_opt_string(vec: Option<Vec<u8>>) -> Option<String> {
    if vec.is_some() {
        Some(String::from_utf8_lossy(&vec.unwrap()).to_string())
    } else {
        None
    }
}

fn array_to_u32(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) <<  8) +
    ((array[3] as u32) <<  0)
}

pub async fn get(id: String) -> WithStatus<Json> {
    let query_response = &query("SELECT username, avatar, bio, verified, deleted, flags FROM accounts.users WHERE vanity = ?", vec![id.clone()]).await.response_body().unwrap();

    if query_response.as_cols().unwrap().rows_content.len() == 0 {
        warp::reply::with_status(warp::reply::json(
            &model::Error {
                error: true,
                message: "Unknown user".to_string()
            }
        ), warp::http::StatusCode::NOT_FOUND)
    } else {
        warp::reply::with_status(warp::reply::json(
            &model::User {
                username: String::from_utf8_lossy(&query_response.as_cols().unwrap().rows_content[0][0].clone().into_bytes().unwrap()).to_string(),
                vanity: id,
                avatar: vec_to_opt_string(query_response.as_cols().unwrap().rows_content[0][1].clone().into_bytes()),
                bio: vec_to_opt_string(query_response.as_cols().unwrap().rows_content[0][2].clone().into_bytes()),
                verified: vec_to_bool(&query_response.as_cols().unwrap().rows_content[0][3].clone().into_bytes().unwrap_or_else(|| vec![0])),
                deleted: vec_to_bool(&query_response.as_cols().unwrap().rows_content[0][4].clone().into_bytes().unwrap_or_else(|| vec![0])),
                flags: array_to_u32(&vec_to_array(query_response.as_cols().unwrap().rows_content[0][5].clone().into_bytes().unwrap_or_else(|| vec![0, 0, 0, 0]))),
            }
        ), warp::http::StatusCode::OK)
    }
}