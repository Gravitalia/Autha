use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use axum::{extract::State, Json};
use fpe::ff1::{FlexibleNumeralString, Operations, FF1};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::database::Database;

use super::{ServerError, Valid};

#[derive(Debug, Deserialize, Validate)]
pub struct Body {
    #[validate(length(min = 2, max = 15))]
    vanity: String,
    #[validate(email(message = "Email must be formated."))]
    email: String,
    #[validate(length(min = 8, message = "Password must contain at least 8 characters."))]
    password: String,
    _captcha: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Response {
    vanity: String,
    token: String,
    locale: String,
}

pub async fn create(
    State(db): State<Database>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>, ServerError> {
    let email = {
        const RADIX: u32 = 256;

        std::env::var("AES_KEY")
            .ok()
            .and_then(|key| hex::decode(&key).ok())
            .and_then(|key| FF1::<aes::Aes256>::new(&key, RADIX).ok())
            .and_then(|ff| {
                let email: Vec<u16> = body.email.encode_utf16().collect();
                let email_length = email.len();

                ff.encrypt(&[], &FlexibleNumeralString::from(email))
                    .ok()
                    .map(|encrypted| hex::encode(encrypted.to_be_bytes(RADIX, email_length)))
            })
            .unwrap_or_else(|| body.email)
    };

    let password = {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(Params::DEFAULT_M_COST * 4, 6, Params::DEFAULT_P_COST, None)
            .map_err(|err| ServerError::Internal(err.to_string()))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let password_hash = argon2
            .hash_password(body.password.as_bytes(), &salt)
            .map_err(|err| ServerError::Internal(err.to_string()))?
            .to_string();
        let hash = PasswordHash::new(&password_hash)
            .map_err(|err| ServerError::Internal(err.to_string()))?;

        hash.to_string()
    };

    sqlx::query_scalar!(
        r#"INSERT INTO "user" (vanity, username, email, password) values ($1, $2, $3, $4)"#,
        body.vanity,
        body.username,
        email,
        password
    )
    .fetch_one(&db.postgres)
    .await
    .on_constraint("user_username_key", |_| {
        ServerError::Internal(String::default())
    })
    .on_constraint("user_email_key", |_| {
        ServerError::Internal(String::default())
    })?;

    Ok(Json(Response {
        vanity: String::default(),
        token: String::default(),
        locale: String::default(),
    }))
}
