use reqwest::{Client, header::HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Deserialize, Serialize)]
struct SiteVerifyResponse {
    success: bool,
    challenge_ts: Option<String>,
    hostname: Option<String>,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
    action: Option<String>,
    cdata: Option<String>,
}

/// Send a request to Cloudflare for check if Turnstile token is valid
pub async fn check_turnstile(token: String) -> Result<bool> {
    let mut data = HashMap::new();
    data.insert("secret", dotenv::var("TURNSTILE_SECRET").expect("Missing env `TURNSTILE_SECRET`"));
    data.insert("response", token);

    let res = Client::new().post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&data)
        .send()
        .await?
        .json::<SiteVerifyResponse>()
        .await?;

    Ok(res.success)
}

/// Send a request to the URL for delete account
pub async fn delete_account(url: String, vanity: String) -> Result<bool> {
    let auth_header_value = HeaderValue::from_str(&dotenv::var("GLOBAL_AUTH").expect("Missing env `GLOBAL_AUTH`"))?;

    let res = Client::new().delete(url+"/account/deletion?user="+&vanity)
    .header("authorization", auth_header_value)
    .send()
    .await?;

    Ok(res.status() == StatusCode::OK)
}