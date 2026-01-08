//! Send emails to user for important updates.

use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use lapin::options::{BasicPublishOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::uri::{
    AMQPAuthority, AMQPQueryString, AMQPScheme, AMQPUri, AMQPUserInfo,
};
use lapin::{
    BasicProperties, Channel, Connection, ConnectionProperties, RecoveryConfig,
};
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::OsRng;
use serde::Serialize;
use url::Url;

use crate::config::Mail;
use crate::error::{Result, ServerError};
use crate::user::User;

const DEFAULT_AMPQ_HOST: &str = "localhost";
const DEFAULT_AMPQ_PORT: u16 = 5672;
const DEFAULT_AMPQ_VHOST: &str = "/";

const CONTENT_ENCODING: &str = "utf8";
const CONTENT_TYPE: &str = "application/cloudevents+json";
const DATA_CONTENT_TYPE: &str = "application/json";
const CLOUDEVENT_VERSION: &str = "1.0";
const ID_LENGTH: usize = 12;

/// Maily templates list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Template {
    /// Provide user variety of explanations.
    Welcome,
    /// Alert user of a personal data update.
    DataUpdate,
}

#[derive(Debug, Serialize)]
struct Cloudevent<'a> {
    specversion: &'static str,
    r#type: &'static str,
    source: &'static str,
    id: String,
    time: String,
    datacontenttype: &'static str,
    data: Content<'a>,
}

#[derive(Debug, Serialize)]
struct Content<'a> {
    locale: Option<Cow<'a, str>>,
    to: Cow<'a, str>,
    template: Template,
    username: Cow<'a, str>,
}

/// Maily instance manager.
#[derive(Debug, Clone, Default)]
pub struct MailManager {
    queue: String,
    conn: Option<Arc<Connection>>,
}

impl MailManager {
    /// Create a new [`MailManager`].
    pub async fn new(config: &Mail) -> Result<Self> {
        let addr = Url::parse(&config.address)?;
        let uri = AMQPUri {
            scheme: AMQPScheme::from_str(addr.scheme())
                .map_err(|_| ServerError::InvalidScheme)?,
            authority: AMQPAuthority {
                userinfo: AMQPUserInfo {
                    username: config.username.clone(),
                    password: config.password.clone(),
                },
                host: addr.host_str().unwrap_or(DEFAULT_AMPQ_HOST).into(),
                port: addr.port().unwrap_or(DEFAULT_AMPQ_PORT),
            },
            vhost: config
                .vhost
                .clone()
                .unwrap_or(DEFAULT_AMPQ_VHOST.to_string()),
            query: AMQPQueryString {
                channel_max: config.pool,
                ..Default::default()
            },
        };

        let recovery_config =
            RecoveryConfig::default().auto_recover_connection();
        let conn_config = ConnectionProperties::default()
            .with_connection_name("autha_maily_client".into())
            .with_experimental_recovery_config(recovery_config);
        let conn = Connection::connect_uri(uri, conn_config).await?;

        tracing::info!(%addr, "rabbitmq connected");

        tracing::debug!(queue = config.queue, "rabbitmq queue created");

        Ok(Self {
            queue: config.queue.clone(),
            conn: Some(Arc::new(conn)),
        })
    }

    async fn create_channel(
        conn: Arc<Connection>,
        queue: &str,
    ) -> Result<Channel> {
        let channel = conn.create_channel().await?;
        channel
            .queue_declare(
                queue,
                QueueDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;
        Ok(channel)
    }

    fn create_event(data: Content) -> Cloudevent {
        let id = Alphanumeric.sample_string(&mut OsRng, ID_LENGTH);
        Cloudevent {
            specversion: CLOUDEVENT_VERSION,
            r#type: "com.gravitalia.email",
            source: "com.gravitalia.autha",
            id,
            time: Utc::now().with_timezone(&Utc).to_rfc3339(),
            datacontenttype: DATA_CONTENT_TYPE,
            data,
        }
    }

    /// Publish event for a specific user.
    pub async fn publish_event(
        &self,
        template: Template,
        email: &str,
        user: &User,
    ) -> Result<()> {
        let Some(conn) = &self.conn else {
            tracing::debug!(?template, "failed to send event");
            return Ok(());
        };
        let channel =
            Self::create_channel(Arc::clone(conn), &self.queue).await?;

        tracing::trace!(?template, "event sent");

        let content = Content {
            locale: Some(Cow::from(&user.locale)),
            username: Cow::from(&user.username),
            to: Cow::from(email),
            template,
        };
        let payload = Self::create_event(content);
        let payload = serde_json::to_string(&payload)?;

        channel
            .basic_publish(
                "",
                &self.queue,
                BasicPublishOptions::default(),
                payload.as_bytes(),
                BasicProperties::default()
                    .with_content_encoding(CONTENT_ENCODING.into())
                    .with_content_type(CONTENT_TYPE.into()),
            )
            .await?;

        Ok(())
    }
}
