use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// Make a request to Cloudflare to check if Turnstile token is valid.
pub async fn check_turnstile(key: String, token: String) -> Result<bool> {
    let mut data = HashMap::new();
    data.insert("secret", key);
    data.insert("response", token);

    let res = Client::new()
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&data)
        .send()
        .await?
        .json::<SiteVerifyResponse>()
        .await?;

    Ok(res.success)
}
