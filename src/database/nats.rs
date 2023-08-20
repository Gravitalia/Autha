use anyhow::Result;
use async_nats::jetstream::{self, Context};

/// Inits NATS (jetstream) connection
pub async fn init() -> Result<Option<Context>> {
    if std::env::var("PUBLISH_UPDATES")
        .unwrap_or_else(|_| false.to_string())
        .parse::<bool>()
        .unwrap()
    {
        let client = async_nats::connect(
            std::env::var("NATS_URL")
                .unwrap_or_else(|_| "nats://localhost:4222".to_string()),
        )
        .await?;

        Ok(Some(jetstream::new(client)))
    } else {
        log::warn!("NATS not started: missing PUBLISH_UPDATES boolean key.");

        Ok(None)
    }
}

/// Publish a message to NATS with "profile_update" as subject
pub async fn publish(
    jetstream: Context,
    message: crate::model::user::UpdatedUser,
) -> Result<()> {
    jetstream
        .publish(
            "profile_update".to_string(),
            serde_json::to_vec(&message)?.into(),
        )
        .await? // Sends data
        .await?; // wait untile publish acknowledgement

    Ok(())
}
