use anyhow::{bail, Result};
use remini::remini_client::ReminiClient;
use remini::Request;

pub mod remini {
    tonic::include_proto!("remini");
}

/// Statistically predicts whether the image supplied in the buffer contains a trace of nudity.
pub async fn is_nude(url: String, buffer: &[u8]) -> Result<bool> {
    let request = tonic::Request::new(Request {
        model: "corpus".to_string(),
        data: buffer.to_vec(),
    });

    let response = ReminiClient::connect(url)
        .await?
        .predict(request)
        .await?
        .into_inner();

    if response.error {
        log::error!(
            "gRPC Remini Predict haven't achieved request: {}",
            response.message
        );
        bail!("invalid response message");
    }

    Ok(matches!(response.message.as_str(), "nude"))
}
