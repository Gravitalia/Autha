use anyhow::Result;
use db::scylla::Scylla;
use regex::Regex;
use warp::reply::{Json, WithStatus};

lazy_static! {
    pub static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    pub static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    pub static ref VANITY: Regex = Regex::new(r"[A-z|0-9|_]{3,16}$").unwrap();
    pub static ref PHONE: Regex = Regex::new(
        r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$"
    )
    .unwrap();
    pub static ref BIRTH: Regex =
        Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

/// Handle create route and check if everything is valid.
pub async fn handle(
    scylla: std::sync::Arc<Scylla>,
    body: crate::model::body::Create,
    ip: String,
    token: Option<String>,
) -> Result<WithStatus<Json>> {
    // Use tokio task if async do not work.
    // Email verification via regex.
    if !EMAIL.is_match(&body.email) {
        return Ok(super::err("Invalid email"));
    }
    // Check password length and its reliability.
    if body.password.len() < 8 && !PASSWORD.is_match(&body.password) {
        return Ok(super::err("Invalid password"));
    }
    // Vanity verification.
    if !VANITY.is_match(&body.vanity) || body.vanity.chars().all(|c| c.is_ascii_digit()) {
        return Ok(super::err("Invalid vanity"));
    }
    // Username length check.
    if body.username.len() > 25 {
        return Ok(super::err("Invalid username"));
    }

    let hashed_email =
        crypto::encrypt::format_preserving_encryption(body.email.encode_utf16().collect())?;

    // Check if account with this email already exists.
    if !scylla
        .connection
        .query(
            "SELECT vanity FROM accounts.users WHERE email = ?",
            vec![hashed_email],
        )
        .await?
        .rows
        .unwrap_or_default()
        .is_empty()
    {
        return Ok(super::err("Email already used".to_string()));
    }

    // Check if account with this vanity already exists.
    if !scylla
        .connection
        .query(
            "SELECT vanity FROM accounts.users WHERE vanity = ?",
            vec![body.vanity.clone()],
        )
        .await?
        .rows
        .unwrap_or_default()
        .is_empty()
    {
        return Ok(super::err("Vanity already used".to_string()));
    }

    // Also check if user is not trying to use a protected vanity.
    if [
        "explore",
        "callback",
        "home",
        "blogs",
        "blog",
        "gravitalia",
        "suba",
        "support",
        "oauth",
        "upload",
        "new",
        "settings",
        "parameters",
        "fallback",
    ]
    .contains(&body.vanity.as_str())
    {
        return Ok(super::err("Vanity already used".to_string()));
    }

    let mut phone: Option<String> = None;
    if let Some(number) = body.phone {
        if !PHONE.is_match(&number) {
            return Ok(super::err("Invalid phone".to_string()));
        } else {
            let (nonce, encrypted) =
                crypto::encrypt::chacha20_poly1305(number.as_bytes().to_vec())?;

            let uuid = uuid::Uuid::new_v4().to_string();

            scylla
                .connection
                .query(
                    "INSERT INTO accounts.salts ( id, salt ) VALUES (?, ?);",
                    vec![uuid.clone(), nonce],
                )
                .await?;

            phone = Some(format!("{}//{}", uuid, encrypted));
        }
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: "OK".to_string(),
        }),
        warp::http::StatusCode::CREATED,
    ))
}
