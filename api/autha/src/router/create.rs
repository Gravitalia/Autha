use crate::helpers::{
    queries::{CREATE_SALT, CREATE_USER},
    token,
};
use crypto::hash::{
    argon2::{argon2, Argon2Configuration},
    sha::sha256,
};
use db::broker::Broker;
use db::{memcache::MemcachePool, scylla::Scylla};
use regex_lite::Regex;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tracing::{error, warn};
use warp::{reject::Rejection, reply::Reply};

const MAX_USERNAME_LENGTH: u8 = 25;
pub(super) const MIN_PASSWORD_LENGTH: u8 = 8;
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
    /// Match emails such as hinome@gravitalia.com or "John Doe"@🏹.com.
    pub static ref EMAIL: Regex = Regex::new(r".+@.+.([a-zA-Z]{2,7})$").unwrap();
    /// Match special characters of the password.
    pub static ref PASSWORD: Regex = Regex::new(r"([0-9|*|]|[$&+,:;=?@#|'<>.^*()%!-])+").unwrap();
    /// Check if vanity is between 3 and 6 characters and if it contains
    /// only upper case, lower case, numbers and underscore.
    static ref VANITY: Regex = Regex::new(r"[A-z|0-9|_]{3,16}$").unwrap();
    /// Match phones number such as (555) 555-1234 and 0611111111.
    pub(super) static ref PHONE: Regex = Regex::new(
        r"^\s*(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\s*$"
    )
    .unwrap();
    /// Match dates like 2018-01-01.
    pub(super) static ref BIRTH: Regex =
        Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$").unwrap();
}

/// Handle create route and check if everything is valid.
#[allow(unused)]
pub async fn handle(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    broker: Arc<Broker>,
    body: crate::model::body::Create,
    token: Option<String>,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    // Use tokio task if async do not work.
    // Email verification via regex.
    if !EMAIL.is_match(&body.email) {
        return Ok(super::err(super::INVALID_EMAIL));
    }

    // Check password length and its reliability.
    if (body.password.len() as u8) < MIN_PASSWORD_LENGTH
        && !PASSWORD.is_match(&body.password)
    {
        return Ok(super::err(super::INVALID_PASSWORD));
    }

    // Vanity verification.
    if !VANITY.is_match(&body.vanity)
        || body.vanity.chars().all(|c| c.is_ascii_digit())
    {
        return Ok(super::err("Invalid vanity"));
    }

    // Username length check.
    if body.username.len() as u8 > MAX_USERNAME_LENGTH
        || body.username.is_empty()
    {
        return Ok(super::err(super::INVALID_USERNAME));
    }

    // Check if locale respects ISO 639-1.
    if isolang::Language::from_639_1(&body.locale).is_none() {
        return Ok(super::err("Invalid locale"));
    }

    let ip = forwarded.unwrap_or_else(|| {
        ip.unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)
        })
        .ip()
        .to_string()
    });

    // Check if user have already created account 5 minutes ago.
    let hashed_ip = sha256(ip.as_bytes());
    if hashed_ip.is_empty() {
        warn!(
            "The IP could not be hashed. This can result in the uncontrolled creation of accounts."
        );
    } else {
        let rate_limit = match memcached
            .get(format!("account_create_{}", hashed_ip))
            .map_err(|_| crate::router::Errors::Unspecified)?
        {
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
                },
                Err(error) => {
                    error!(
                        "Cannot make Cloudflare Turnstile request: {}",
                        error
                    );
                    return Ok(super::err(super::INTERNAL_SERVER_ERROR));
                },
            }
        } else {
            return Ok(super::err(super::INVALID_TURNSTILE));
        }
    }

    let hashed_email = crypto::encrypt::format_preserving_encryption(
        std::env::var("AES256_KEY")
            .unwrap_or_else(|_| super::DEFAULT_AES_KEY.to_string()),
        body.email.encode_utf16().collect(),
    )
    .map_err(|_| crate::router::Errors::Unspecified)?;

    // Check if account with this email already exists.
    if !scylla
        .connection
        .query(
            "SELECT vanity FROM accounts.users WHERE email = ?",
            vec![&hashed_email],
        )
        .await
        .map_err(|_| crate::router::Errors::Unspecified)?
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
        .await
        .map_err(|_| crate::router::Errors::Unspecified)?
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

    let mut phone: Option<String> = None;
    if let Some(number) = body.phone {
        if !PHONE.is_match(&number) {
            return Ok(super::err(super::INVALID_PHONE));
        } else {
            let (nonce, encrypted) =
                crypto::encrypt::chacha20_poly1305(number.into())
                    .map_err(|_| crate::router::Errors::Unspecified)?;

            let uuid = uuid::Uuid::new_v4();

            if let Some(query) = CREATE_SALT.get() {
                scylla
                    .connection
                    .execute(query, (&uuid, &nonce))
                    .await
                    .map_err(|_| crate::router::Errors::Unspecified)?;
            } else {
                error!("Prepared queries do not appear to be initialized.");
                return Err(crate::router::Errors::Unspecified.into());
            }

            // Set primary key (to get nonce) and encrypted phone.
            phone = Some(format!("{}//{}", uuid, encrypted));
        }
    }

    let mut birthdate: Option<String> = None;
    if let Some(birth) = body.birthdate.clone() {
        let dates: Vec<&str> = birth.split('-').collect();

        // Check if user is 13 years old at least.
        if !BIRTH.is_match(&birth)
            || 13
                > crate::helpers::get_age(
                    dates[0].parse::<i16>().unwrap_or_default(),
                    dates[1].parse::<i8>().unwrap_or_default(),
                    dates[2].parse::<i8>().unwrap_or_default(),
                )
                .map_err(|_| crate::router::Errors::Unspecified)?
        {
            return Ok(super::err(super::INVALID_BIRTHDATE));
        } else {
            let (nonce, encrypted) =
                crypto::encrypt::chacha20_poly1305(birth.into())
                    .map_err(|_| crate::router::Errors::Unspecified)?;

            let uuid = uuid::Uuid::new_v4().to_string();

            if let Some(query) = CREATE_SALT.get() {
                scylla
                    .connection
                    .execute(query, (&uuid, &nonce))
                    .await
                    .map_err(|_| crate::router::Errors::Unspecified)?;
            } else {
                error!("Prepared queries do not appear to be initialized.");
                return Err(crate::router::Errors::Unspecified.into());
            }

            // Set primary key (to get nonce) and encrypted birthdate.
            birthdate = Some(format!("{}//{}", uuid, encrypted));
        }
    }

    // Create user on database.
    if let Some(query) = CREATE_USER.get() {
        let argon_config = Argon2Configuration {
            memory_cost: std::env::var("MEMORY_COST")
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or(262144),
            round: std::env::var("ROUND")
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or(1),
            lanes: 8,
            secret: std::env::var("KEY").unwrap_or_else(|_| "KEY".to_string()),
            hash_length: std::env::var("HASH_LENGTH")
                .unwrap_or_default()
                .parse::<u32>()
                .unwrap_or(16),
        };

        if let Err(error) = scylla
            .connection
            .execute(
                query,
                (
                    &body.vanity,
                    &hashed_email,
                    &body.username,
                    &argon2(
                        argon_config,
                        body.password.as_bytes(),
                        Some(body.vanity.as_bytes()),
                    )
                    .map_err(|_| crate::router::Errors::Unspecified)?,
                    &body.locale,
                    &phone.unwrap_or_default(), // Never insert directly a null value, otherwhise it will create a tombestone.
                    &birthdate.unwrap_or_default(), // Never insert directly a null value, otherwhise it will create a tombestone.
                ),
            )
            .await
        {
            error!("Cannot create user: {}", error);
        }
    } else {
        error!("Prepared queries do not appear to be initialized.");
    }

    let token = match token::create(&scylla, &body.vanity, ip).await {
        Ok(res) => res,
        Err(error) => {
            error!("Cannot create user token: {}", error);
            return Ok(super::err("Cannot create token"));
        },
    };

    if let Err(error) =
        memcached.set(format!("account_create_{}", hashed_ip), 1)
    {
        warn!("Cannot set global rate limiter when create. This could lead to massive spam! Error: {}", error);
    }

    #[cfg(any(feature = "kafka", feature = "rabbitmq"))]
    {
        use crate::model::{broker::Message, user::User};
        use chrono::Utc;
        use crypto::random_string;

        let topic = format!(
            "{}.autha.user",
            std::env::var("SERVICE_NAME").unwrap_or("gravitalia".to_string())
        );
        let new_user = serde_json::to_string(&Message {
            id: random_string(36),
            datacontenttype: "application/json; charset=utf-8".to_string(),
            data: User {
                username: body.username,
                vanity: body.vanity.clone(),
                avatar: None,
                bio: None,
                email: None,
                birthdate: body.birthdate,
                phone: None,
                verified: false,
                deleted: false,
                flags: 0,
            },
            source: format!("//autha.gravitalia.com/users/{}", body.vanity),
            specversion: "1.0".to_string(),
            time: Some(Utc::now().to_rfc3339()),
            r#type: "com.gravitalia.autha.user.v1.new_account".to_string(),
        })
        .map_err(|_| crate::router::Errors::Unspecified)?;

        match <std::sync::Arc<Broker> as Into<Broker>>::into(broker) {
            #[cfg(feature = "kafka")]
            Broker::Kafka(func) => func
                .publish(&topic, &new_user)
                .map_err(|_| crate::router::Errors::Unspecified)?,
            #[cfg(feature = "rabbitmq")]
            Broker::RabbitMQ(func) => func
                .publish(&topic, &new_user)
                .await
                .map_err(|_| crate::router::Errors::Unspecified)?,
            // Won't happend.
            _ => {},
        }
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
