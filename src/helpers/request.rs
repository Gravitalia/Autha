use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use reqwest::Client;

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

pub async fn check_turnstile(token: String) -> Result<bool, Box<dyn std::error::Error>>  {
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