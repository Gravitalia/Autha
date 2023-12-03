use anyhow::Result;
use db::memcache::{MemcacheManager, MemcachePool};
use db::scylla::Scylla;
use regex::Regex;
use warp::reply::{Json, WithStatus};

use crate::helpers;

const MAX_USERNAME_LENGTH: u8 = 25;
pub(super) const MIN_PASSWORD_LENGTH: u8 = 25;
const INVALID_VANITY: [&str; 14] = [
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
];

lazy_static! {
    pub static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    pub static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    static ref VANITY: Regex = Regex::new(r"[A-z|0-9|_]{3,16}$").unwrap();
    static ref PHONE: Regex = Regex::new(
        r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$"
    )
    .unwrap();
    static ref BIRTH: Regex =
        Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

/// Handle create route and check if everything is valid.
pub async fn handle(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Create,
    token: Option<String>,
    ip: String,
) -> Result<WithStatus<Json>> {
    // Use tokio task if async do not work.
    // Email verification via regex.
    if !EMAIL.is_match(&body.email) {
        return Ok(super::err(super::INVALID_EMAIL));
    }

    // Check password length and its reliability.
    if (body.password.len() as u8) < MIN_PASSWORD_LENGTH && !PASSWORD.is_match(&body.password) {
        return Ok(super::err(super::INVALID_PASSWORD));
    }

    // Vanity verification.
    if !VANITY.is_match(&body.vanity) || body.vanity.chars().all(|c| c.is_ascii_digit()) {
        return Ok(super::err("Invalid vanity"));
    }

    // Username length check.
    if body.username.len() as u8 > MAX_USERNAME_LENGTH || body.username.is_empty() {
        return Ok(super::err("Invalid username"));
    }

    // Check if locale respects ISO 639-1.
    if isolang::Language::from_639_1(&body.locale).is_none() {
        return Ok(super::err("Invalid locale"));
    }

    // Check if user have already created account 5 minutes ago.
    let hashed_ip = crypto::hash::sha256(ip.as_bytes()).unwrap_or_default();
    if hashed_ip.is_empty() {
        log::warn!(
            "The IP could not be hashed. This can result in the uncontrolled creation of accounts."
        );
    } else {
        let rate_limit = match memcached.get(format!("account_create_{}", hashed_ip))? {
            Some(r) => r.parse::<u16>().unwrap_or(0),
            None => 0,
        };

        if rate_limit >= 1 {
            return Ok(warp::reply::with_status(
                warp::reply::json(&crate::model::error::Error {
                    error: true,
                    message: super::ERROR_RATE_LIMITED.into(),
                }),
                warp::http::StatusCode::TOO_MANY_REQUESTS,
            ));
        }
    }

    // Check if Cloudflare Turnstile token is valid.
    // If no Cloudflare Turnstile key is provided in environnement, don't check.
    if !std::env::var("TURNSTILE_SECRET")
        .unwrap_or_default()
        .is_empty()
    {
        if let Some(cf_token) = token {
            match crate::helpers::request::check_turnstile(
                std::env::var("TURNSTILE_SECRET").unwrap_or_default(),
                cf_token,
            )
            .await
            {
                Ok(res) => {
                    if !res {
                        return Ok(super::err(super::INVALID_TURNSTILE));
                    }
                }
                Err(error) => {
                    log::error!("Cannot make Cloudflare Turnstile request: {}", error);
                    return Ok(super::err(super::INTERNAL_SERVER_ERROR));
                }
            }
        } else {
            return Ok(super::err(super::INVALID_TURNSTILE));
        }
    }

    let hashed_email =
        crypto::encrypt::format_preserving_encryption(body.email.encode_utf16().collect())?;

    // Check if account with this email already exists.
    if !scylla
        .connection
        .query(
            "SELECT vanity FROM accounts.users WHERE email = ?",
            vec![&hashed_email],
        )
        .await?
        .rows
        .unwrap_or_default()
        .is_empty()
    {
        return Ok(super::err("Email already used"));
    }

    // Check if account with this vanity already exists.
    if !scylla
        .connection
        .query(
            "SELECT vanity FROM accounts.users WHERE vanity = ?",
            vec![&body.vanity],
        )
        .await?
        .rows
        .unwrap_or_default()
        .is_empty()
    {
        return Ok(super::err("Vanity already used"));
    }

    // Also check if user is not trying to use a protected vanity.
    if INVALID_VANITY.contains(&body.vanity.as_str()) {
        return Ok(super::err("Vanity already used"));
    }

    // Prepare the query to be faster if user set both phone and birthdate.
    // It will avoid database to make a query pasing.
    let insert_salt_query = scylla
        .connection
        .prepare("INSERT INTO accounts.salts ( id, salt ) VALUES (?, ?)")
        .await?;

    let mut phone: Option<String> = None;
    if let Some(number) = body.phone {
        if !PHONE.is_match(&number) {
            return Ok(super::err("Invalid phone"));
        } else {
            let (nonce, encrypted) =
                crypto::encrypt::chacha20_poly1305(number.as_bytes().to_vec())?;

            let uuid = uuid::Uuid::new_v4();

            scylla
                .connection
                .execute(&insert_salt_query, (&uuid, &nonce))
                .await?;

            // Set primary key (to get nonce) and encrypted phone.
            phone = Some(format!("{}//{}", uuid, encrypted));
        }
    }

    let mut birthdate: Option<String> = None;
    if let Some(birth) = body.birthdate {
        let dates: Vec<&str> = birth.split('-').collect();

        // Check if user is 13 years old at least.
        if !BIRTH.is_match(&birth)
            || 13
                > crate::helpers::get_age(
                    dates[0].parse::<i16>().unwrap_or_default(),
                    dates[1].parse::<i8>().unwrap_or_default(),
                    dates[2].parse::<i8>().unwrap_or_default(),
                )?
        {
            return Ok(super::err("Too young"));
        } else {
            let (nonce, encrypted) = crypto::encrypt::chacha20_poly1305(birth.as_bytes().to_vec())?;

            let uuid = uuid::Uuid::new_v4().to_string();

            scylla
                .connection
                .execute(&insert_salt_query, (&uuid, &nonce))
                .await?;

            // Set primary key (to get nonce) and encrypted birthdate.
            birthdate = Some(format!("{}//{}", uuid, encrypted));
        }
    }

    // Use prepared query to properly balance.
    // The values of not set (avatar, banner and bio) columns will be set as null
    // but would not create tombestone unless they are set directly as null values.
    let insert_user_query = scylla
    .connection
    .prepare(
        "INSERT INTO accounts.users ( vanity, email, username, password, locale, phone, birthdate, flags, deleted, verified, expire_at ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, false, false, 0)"
    )
    .await?;

    // Create user on database.
    if let Err(error) = scylla
        .connection
        .execute(
            &insert_user_query,
            (
                &body.vanity,
                &hashed_email,
                &body.username,
                &crypto::hash::argon2(body.password.as_bytes(), body.vanity.as_bytes()),
                &body.locale,
                &phone.unwrap_or_default(), // Never insert directly a null value, otherwhise it will create a tombestone.
                &birthdate.unwrap_or_default(), // Never insert directly a null value, otherwhise it will create a tombestone.
            ),
        )
        .await
    {
        log::error!("Cannot create user: {}", error);
    }

    let token = match helpers::token::create(&scylla, &body.vanity, ip).await {
        Ok(res) => res,
        Err(error) => {
            log::error!("Cannot create user token: {}", error);
            return Ok(super::err("Cannot create token"));
        }
    };

    if let Err(error) = memcached.set(format!("account_create_{}", hashed_ip), 1) {
        log::warn!("Cannot set global rate limiter when create. This could lead to massive spam! Error: {}", error)
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::Token {
            vanity: body.vanity,
            token,
            user_settings: crate::model::config::UserSettings {
                locale: body.locale,
            },
        }),
        warp::http::StatusCode::CREATED,
    ))
}
