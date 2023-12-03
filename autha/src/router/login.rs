use crate::router::create::{EMAIL, MIN_PASSWORD_LENGTH, PASSWORD};
use anyhow::{anyhow, Result};
use db::memcache::{MemcacheManager, MemcachePool};
use db::scylla::Scylla;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::reply::{Json, WithStatus};

/// Handle login route.
pub async fn handle(
    scylla: std::sync::Arc<Scylla>,
    memcached: MemcachePool,
    body: crate::model::body::Login,
    token: Option<String>,
    ip: String,
) -> Result<WithStatus<Json>> {
    // Make pre-check to avoid unnecessary requests.
    if !EMAIL.is_match(&body.email) {
        return Ok(super::err(super::INVALID_EMAIL));
    }

    if (body.password.len() as u8) < MIN_PASSWORD_LENGTH && !PASSWORD.is_match(&body.password) {
        return Ok(super::err(super::INVALID_PASSWORD));
    }

    // Check that the user has not tried to connect 5 times in the last 5 minutes.
    let hashed_ip = crypto::hash::sha256(ip.as_bytes()).unwrap_or_default();
    let rate_limit = if hashed_ip.is_empty() {
        log::warn!("The IP could not be hashed. This can result in massive trying of connection.");

        0
    } else {
        match memcached.get(format!("account_login_{}", hashed_ip))? {
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
    if let Err(error) = memcached.set(format!("account_login_{}", hashed_ip), rate_limit + 1) {
        log::warn!("Cannot set global rate limiter when create. This could lead to massive spam! Error: {}", error)
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

    let rows = scylla
        .connection
        .query(
            "SELECT vanity, password, deleted, mfa_code, expire_at, locale FROM accounts.users WHERE email = ?",
            vec![&hashed_email],
        )
        .await?
        .rows_typed::<(String, String, bool, Option<String>, i64, String)>()?
        .collect::<Vec<_>>();

    // Check if email is in use. Otherwise return error.
    if rows.is_empty() {
        return Ok(super::err(super::INVALID_EMAIL));
    }

    let (vanity, password, deleted, mfa, expire, locale) = rows[0].clone().unwrap();

    // Check if account is deleted or even suspended.
    let timestamp_ms: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()?;

    if deleted && expire == 0 {
        // Account is totaly suspended and can't be recovered.
        return Ok(crate::router::err("Account suspended"));
    } else if deleted && expire >= timestamp_ms {
        // Account is deleted but data are kept for 2 months.
        return Ok(crate::router::err("Deleted account: recoverable"));
    } else if deleted && expire <= timestamp_ms {
        // Account is totaly deleted, only email and vanity are kept.
        return Ok(crate::router::err(super::INVALID_EMAIL));
    }

    // Check if passwords are matching.
    if !crypto::hash::check_argon2(password, body.password.as_bytes(), vanity.as_bytes())? {
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
            .await?
            .rows
            .unwrap_or_default();

        if res.is_empty() {
            log::error!("Cannot get salt for decrypt MFA code.");
            return Ok(super::err(super::INTERNAL_SERVER_ERROR));
        }

        let nonce: [u8; 12] = hex::decode(
            res[0].columns[0]
                .as_ref()
                .ok_or_else(|| anyhow!("No reference"))?
                .as_text()
                .ok_or_else(|| anyhow!("Cannot convert to string"))?,
        )?
        .try_into()
        .unwrap_or_default();

        // Save MFA code in clear, not in base32 => for generate key, use helpers::random_string with 10 as length
        if totp_lite::totp_custom::<totp_lite::Sha1>(
            30,
            6,
            crypto::decrypt::chacha20_poly1305(nonce, cypher.as_bytes().to_vec())?.as_ref(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        ) != body.mfa.unwrap_or_default()
        {
            return Ok(crate::router::err("Invalid MFA"));
        }
    }

    let token = match crate::helpers::token::create(&scylla, &vanity, ip).await {
        Ok(res) => res,
        Err(error) => {
            log::error!("Cannot create user token: {}", error);
            return Ok(super::err("Cannot create token"));
        }
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::response::Token {
            vanity,
            token,
            user_settings: crate::model::config::UserSettings { locale },
        }),
        warp::http::StatusCode::CREATED,
    ))
}
