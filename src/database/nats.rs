use anyhow::Result;
use async_nats::jetstream::{self, Context};

/// Inits NATS (jetstream) connection
pub async fn init(
    config: &crate::model::config::Config,
) -> Result<Option<Context>> {
    if config.database.nats.publish {
        let client =
            async_nats::connect(config.database.nats.host.clone()).await?;

        Ok(Some(jetstream::new(client)))
    } else {
        log::warn!("NATS not started: publish is not activated");

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
