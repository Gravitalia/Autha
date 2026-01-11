//! Delete user from database with 30-day retention.

use axum::Extension;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use validator::Validate;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::router::Valid;
use crate::user::UserService;
use crate::{AppState, ServerError};

#[derive(Debug, Validate, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    totp_code: Option<String>,
    #[validate(length(
        min = 8,
        message = "Password must contain at least 8 characters."
    ))]
    password: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<UserService>,
    Valid(body): Valid<Body>,
) -> Result<(), ServerError> {
    state
        .crypto
        .pwd
        .verify_password(&body.password, &user.data.password)?;
    state.crypto.symmetric.check_totp(
        body.totp_code.as_deref(),
        user.data.totp_secret.as_deref(),
    )?;

    user.delete().await?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use axum::http::StatusCode;
    use serde_json::json;
    use sqlx::{Pool, Postgres};

    use crate::*;

    #[sqlx::test(fixtures("../../../fixtures/users.sql"))]
    async fn test_delete_handler(pool: Pool<Postgres>) {
        let state = router::state(pool);
        let app = app(state.clone());

        let req_body = router::users::delete::Body {
            totp_code: None,
            password: "StRong_Pa§$W0rD".to_string(),
        };
        let response = make_request(
            Some(&state),
            app.clone(),
            Method::DELETE,
            "/users/@me",
            json!(req_body).to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        // Admin must be deleted.
        let response = make_request(
            None,
            app,
            Method::GET,
            "/users/admin",
            String::default(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
