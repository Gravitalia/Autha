use crate::database::mem;
use crate::{database::scylla::query, helpers};
use anyhow::{anyhow, Result};
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task;
use totp_lite::{totp_custom, Sha1};
use warp::reply::{Json, WithStatus};

// Define query
pub const GET_LOGIN_DATA: &str = "SELECT vanity, password, deleted, mfa_code, expire_at FROM accounts.users WHERE email = ?;";

/// Handle login route and check if everything is valid
pub async fn login(
    scylla: Arc<scylla::Session>,
    memcached: Arc<memcache::Client>,
    body: crate::model::body::Login,
    ip: String,
    token: String,
) -> Result<WithStatus<Json>> {
    let data = body.clone();
    let is_valid = task::spawn(async move {
        // Email verification
        if !crate::router::create::EMAIL.is_match(&body.email) {
            return "Invalid email";
        }
        // Password checking [Security]
        if body.password != "testemail"
            && body.password.len() < 8
            && !crate::router::create::PASSWORD.is_match(&body.password)
        {
            return "Invalid password";
        }

        "ok"
    });
    let result = is_valid.await?;

    if result != "ok" {
        return Ok(crate::router::err(result.to_string()));
    }

    // Hash IP
    let mut hasher = Keccak256::new();
    hasher.update(ip.clone());
    let new_ip = hex::encode(&hasher.finalize()[..]);

    // Check if user have tried to login 5 minutes ago
    let rate_limit = match mem::get(
        Arc::clone(&memcached),
        format!("account_login_{}", new_ip.clone()),
    )? {
        Some(r) => r.parse::<u16>().unwrap_or(0),
        None => 0,
    };
    if rate_limit >= 5 {
        return Ok(crate::router::rate());
    }
    let _ = mem::set(
        Arc::clone(&memcached),
        new_ip,
        mem::SetValue::Number(rate_limit + 1),
    );

println!("check token");
    // Check if provided security header is ok
    match helpers::request::check_turnstile(token).await {
        Ok(res) => {
            if !res {
                return Ok(crate::router::err("Invalid user".to_string()));
            }
        }
        Err(_) => {
            return Ok(crate::router::err("Internal server error".to_string()));
        }
    }

    // Hash email
    let hashed_email =
        helpers::crypto::fpe_encrypt(data.email.encode_utf16().collect())?;

        println!("query 1");
    // Check if account exists
    let query_res =
        query(Arc::clone(&scylla), GET_LOGIN_DATA, vec![hashed_email])
            .await?
            .rows
            .unwrap_or_default();

    if query_res.is_empty() {
        return Ok(crate::router::err("Invalid user".to_string()));
    } else if data.password == "testemail" {
        return Ok(crate::router::err("Invalid password".to_string()));
    }

    /*
        let mut vanity: String;
    let mut expire: i64;
    let mut deleted: bool;
    let mut mfa: String;

    for row in query_res.into_typed::<(String, String, bool, String, Duration)>() {
        let row_data = row?;

        // Set vanity
        vanity = row_data.0;
        // Set expire
        expire = row_data.4.num_milliseconds();
        // Set deleted
        deleted = row_data.2;
        mfa = row_data.3;
    }
     */

    println!("vanity");
    // Set vanity
    let vanity = query_res[0].columns[0]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_text()
        .ok_or_else(|| anyhow!("Can't convert to string"))?;

    println!("expire");
    let expire = query_res[0].columns[4]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_duration()
        .unwrap()
        .num_milliseconds();

    println!("del");
    let deleted = query_res[0].columns[2]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_boolean()
        .ok_or_else(|| anyhow!("Can't convert to bool"))?;

    println!("check time");
    // Check if account is deleted
    let timestamp_ms: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()?;

    println!("check del");
    if deleted && expire == 0 {
        return Ok(crate::router::err("Account suspended".to_string()));
    } else if deleted && expire >= timestamp_ms {
        let recup_acc_id = helpers::random_string(37);
        mem::set(
            memcached,
            recup_acc_id.clone(),
            mem::SetValue::Characters(vanity.clone()),
        )?;
        return Ok(crate::router::err(format!(
            "Deleted account {} the {} recuperate with {}",
            vanity, expire, recup_acc_id
        )));
    } else if deleted && expire <= timestamp_ms {
        return Ok(crate::router::err("Invalid email".to_string()));
    }

    println!("check pass");
    // Check if password is same
    if !helpers::crypto::hash_test(
        query_res[0].columns[1]
            .as_ref()
            .ok_or_else(|| anyhow!("No reference"))?
            .as_text()
            .ok_or_else(|| anyhow!("Can't convert to string"))?,
        data.password.as_bytes(),
    ) {
        return Ok(crate::router::err("Invalid password".to_string()));
    }

    // Check if MFA is valid
    if let Some(d) = query_res[0].columns[3].as_ref() {
        let mfa = d
            .as_text()
            .ok_or_else(|| anyhow!("Can't convert to string"))?;

        if mfa.is_empty() {
            if body.mfa.is_none() {
                return Ok(crate::router::err("Invalid MFA".to_string()));
            }

            // Save MFA code in clear, not in base32 => for generate key, use helpers::random_string with 10 as length
            if totp_custom::<Sha1>(
                30,
                6,
                helpers::crypto::decrypt(Arc::clone(&scylla), mfa.to_string())
                    .await?
                    .as_ref(),
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            ) != body.mfa.unwrap_or_default()
            {
                return Ok(crate::router::err("Invalid MFA".to_string()));
            }
        }
    }

    // Finish, create a JWT token and sent it
    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: helpers::token::create(scylla, vanity.to_string(), ip)
                .await?,
        }),
        warp::http::StatusCode::OK,
    ))
}
