use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{database::Database, user::User};

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
    user: User,
    token: String,
}

pub async fn create(
    State(db): State<Database>,
    Valid(body): Valid<Body>,
) -> Result<Json<Response>, ServerError> {
    let email = crate::crypto::email_encryption(body.email);

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

    sqlx::query!(
        r#"INSERT INTO "users" (vanity, username, email, password) values ($1, $2, $3, $4)"#,
        body.vanity.to_lowercase(),
        body.vanity,
        email,
        password
    )
    .execute(&db.postgres)
    .await
    .map_err(ServerError::Sql)?;

    let user = User::default()
        .with_vanity(body.vanity.to_lowercase())
        .get(&db.postgres)
        .await?;
    let token = user.generate_token(&db.postgres).await?;

    Ok(Json(Response {
        user: User::default(),
        token,
    }))
}
