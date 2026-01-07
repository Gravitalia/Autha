//! Based on JWK (RFC 7517 <https://datatracker.ietf.org/doc/html/rfc7517>).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::PublicKey;
use p256::elliptic_curve::pkcs8::DecodePublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};

use crate::config::Configuration;
use crate::token::DEFAULT_KID;

// 48 for P384.
const COORD_LEN: usize = 32;
const PREFIX_LEN: usize = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    keys: Vec<Key>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Key {
    crv: String,
    ext: bool,
    key_ops: Vec<String>,
    kty: String,
    x: String,
    y: String,
    kid: String,
    alg: String,
    r#use: String,
}

fn p256_pem_to_jwk(pem: String) -> Option<(String, String)> {
    let public_key = PublicKey::from_public_key_pem(&pem).ok()?;
    let encoded_point = public_key.to_encoded_point(false);
    let full_bytes = encoded_point.as_bytes();
    if full_bytes.len() != PREFIX_LEN + 2 * COORD_LEN || full_bytes[0] != 0x04
    {
        return None;
    }

    let x = &full_bytes[PREFIX_LEN..PREFIX_LEN + COORD_LEN];
    let y = &full_bytes[PREFIX_LEN + COORD_LEN..];

    let x = Base64UrlUnpadded::encode_string(x);
    let y = Base64UrlUnpadded::encode_string(y);

    Some((x, y))
}

pub async fn handler(
    State(config): State<Arc<Configuration>>,
) -> Result<Json<Response>, StatusCode> {
    let token_config = config
        .token
        .clone()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let pem = token_config.public_key_pem;
    let Some((x, y)) = p256_pem_to_jwk(pem) else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let keys = vec![Key {
        key_ops: vec!["verify".to_string()],
        ext: true,
        kty: "EC".into(),
        r#use: "sig".into(),
        kid: token_config.key_id.unwrap_or(DEFAULT_KID.to_string()),
        alg: "ES256".into(),
        x,
        y,
        crv: "P-256".into(),
    }];

    Ok(Json(Response { keys }))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use sqlx::{Pool, Postgres};

    use crate::*;

    #[sqlx::test]
    async fn test_jwks_handler(pool: Pool<Postgres>) {
        // State pool is useless, but required.
        let state = crate::router::state(pool);
        let config = state.config.clone();
        let app = app(state);

        let response = make_request(
            None,
            app,
            Method::GET,
            "/.well-known/jwks.json",
            String::default(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: well_known::jwks::Response =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body.keys[0].kid,
            config
                .token
                .clone()
                .unwrap()
                .key_id
                .unwrap_or(crate::well_known::jwks::DEFAULT_KID.to_string())
        );
        assert_eq!(&body.keys[0].alg, "ES256");
        assert_eq!(&body.keys[0].crv, "P-256");
        assert_eq!(
            &body.keys[0].x,
            "5GWM29JoM3nnJDZBNnSpcF_c8VvUM-CbZS0B--iDoVw"
        );
        assert_eq!(
            &body.keys[0].y,
            "05sMauyuwR6jkoMJB7WuuRhP-ZM25Z6kQSi1F3gNG98"
        );
    }
}
