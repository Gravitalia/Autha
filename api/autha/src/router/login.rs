use crate::router::create::{EMAIL, MIN_PASSWORD_LENGTH, PASSWORD};
use anyhow::anyhow;
use crypto::hash::{argon2::check_argon2, sha::sha256};
use db::{
    libscylla::frame::value::CqlTimestamp, memcache::MemcachePool,
    scylla::Scylla,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, warn};
use warp::{reject::Rejection, reply::Reply};

/// Handle login route.
pub async fn handle(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Login,
    token: Option<String>,
    forwarded: Option<String>,
    ip: Option<SocketAddr>,
) -> Result<impl Reply, Rejection> {
    // Make pre-check to avoid unnecessary requests.
    if !EMAIL.is_match(&body.email) {
        return Ok(super::err(super::INVALID_EMAIL));
    }

    if (body.password.len() as u8) < MIN_PASSWORD_LENGTH
        && !PASSWORD.is_match(&body.password)
    {
        return Ok(super::err(super::INVALID_PASSWORD));
    }

    let ip = forwarded.unwrap_or_else(|| {
        ip.unwrap_or_else(|| {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)
        })
        .ip()
        .to_string()
    });

    // Check that the user has not tried to connect 5 times in the last 5 minutes.
    let hashed_ip = sha256(ip.as_bytes());
    let rate_limit = if hashed_ip.is_empty() {
        warn!("The IP could not be hashed. This can result in massive trying of connection.");

        0
    } else {
        match memcached
            .get(format!("account_login_{}", hashed_ip))
            .map_err(|_| crate::router::Errors::Unspecified)?
        {
            Some(r) => r.parse::<u16>().unwrap_or(0),
            None => 0,
        }
    };

    if rate_limit >= 5 {
        return Ok(warp::reply::with_status(
            warp::reply::json(&crate::model::error::Error {
                error: true,
                message: super::ERROR_RATE_LIMITED.into(),
            }),
            warp::http::StatusCode::TOO_MANY_REQUESTS,
        ));
    }

    // Increment the rate limit counter.
    if let Err(error) =
        memcached.set(format!("account_login_{}", hashed_ip), rate_limit + 1)
    {
        warn!("Cannot set global rate limiter when create. This could lead to massive spam! Error: {}", error)
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

    let rows = scylla
        .connection
        .query(
            "SELECT vanity, password, deleted, mfa_code, expire_at, locale FROM accounts.users WHERE email = ?",
            vec![&hashed_email],
        )
        .await
        .map_err(|_| crate::router::Errors::Unspecified)?
        .rows_typed::<(String, String, bool, Option<String>, CqlTimestamp, String)>()
        .map_err(|_| crate::router::Errors::Unspecified)?
        .collect::<Vec<_>>();

    // Check if email is in use. Otherwise return error.
    if rows.is_empty() {
        return Ok(super::err(super::INVALID_EMAIL));
    }

    let (vanity, password, deleted, mfa, expire, locale) =
        rows[0].clone().unwrap_or_else(|_| {
            (
                String::default(),
                String::default(),
                false,
                None,
                CqlTimestamp(0),
                String::default(),
            )
        });

    // Check if account is deleted or even suspended.
    let timestamp_ms: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .map_err(|_| crate::router::Errors::Unspecified)?;

    if deleted && expire.0 == 0 {
        // Account is totaly suspended and can't be recovered.
        return Ok(crate::router::err("Account suspended"));
    } else if deleted && expire.0 >= timestamp_ms {
        // Account is deleted but data are kept for 2 months.
        return Ok(crate::router::err("Deleted account: recoverable"));
    } else if deleted && expire.0 <= timestamp_ms {
        // Account is totaly deleted, only email and vanity are kept.
        return Ok(crate::router::err(super::INVALID_EMAIL));
    }

    // Check if passwords are matching.
    if !check_argon2(
        std::env::var("KEY")
            .unwrap_or_else(|_| "KEY".to_string())
            .as_bytes(),
        password,
        body.password.as_bytes(),
        Some(vanity.as_bytes()),
    )
    .map_err(|_| crate::router::Errors::Unspecified)?
    {
        return Ok(crate::router::err(super::INVALID_PASSWORD));
    }

    // Check multifactor authentification.
    if let Some(code) = mfa {
        if body.mfa.is_none() {
            return Ok(crate::router::err("MFA required"));
        }

        let (salt, cypher) = code.split_once("//").unwrap_or(("", ""));

        let res = scylla
            .connection
            .query("SELECT salt FROM accounts.salts WHERE id = ?", vec![salt])
            .await
            .map_err(|_| crate::router::Errors::Unspecified)?
            .rows
            .unwrap_or_default();

        if res.is_empty() {
            error!("Cannot get salt for decrypt MFA code.");
            return Ok(super::err(super::INTERNAL_SERVER_ERROR));
        }

        let nonce: [u8; 12] = hex::decode(
            res[0].columns[0]
                .as_ref()
                .ok_or_else(|| anyhow!("No reference"))
                .map_err(|_| crate::router::Errors::Unspecified)?
                .as_text()
                .ok_or_else(|| anyhow!("Cannot convert to string"))
                .map_err(|_| crate::router::Errors::Unspecified)?,
        )
        .map_err(|_| crate::router::Errors::Unspecified)?
        .try_into()
        .unwrap_or_default();

        // Save MFA code in clear, not in base32 => for generate key, use helpers::random_string with 10 as length
        if totp_lite::totp_custom::<totp_lite::Sha1>(
            30,
            6,
            crypto::decrypt::chacha20_poly1305(
                nonce,
                cypher.as_bytes().to_vec(),
            )
            .map_err(|_| crate::router::Errors::Unspecified)?
            .as_ref(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| crate::router::Errors::Unspecified)?
                .as_secs(),
        ) != body.mfa.unwrap_or_default()
        {
            return Ok(crate::router::err("Invalid MFA"));
        }
    }

    let token = match crate::helpers::token::create(&scylla, &vanity, ip).await
    {
        Ok(res) => res,
        Err(error) => {
            error!("Cannot create user token: {}", error);
            return Ok(super::err("Cannot create token"));
        },
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::Token {
            vanity,
            token,
            user_settings: crate::model::config::UserSettings { locale },
        }),
        warp::http::StatusCode::OK,
    ))
}
