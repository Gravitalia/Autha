//! SMTP mailer using RabbitMQ for async email sending.

use std::str::FromStr;
use std::sync::Arc;

use application::error::{ApplicationError, Result, ToInternal};
use application::ports::outbound::Mailer;
use async_trait::async_trait;
use chrono::Utc;
use domain::identity::email::EmailAddress;
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
enum Template {
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
    locale: Option<&'a str>,
    to: &'a str,
    template: Template,
    username: &'a str,
}

/// RabbitMQ-based mailer adapter.
pub struct RabbitMqMailer {
    conn: Option<Arc<Connection>>,
    queue_name: String,
}

impl RabbitMqMailer {
    /// Create a new [`RabbitMqMailer`].
    pub async fn new(
        address: &str,
        username: &str,
        password: &str,
        queue_name: &str,
    ) -> Result<Self> {
        let addr = Url::parse(address).catch()?;
        let uri = AMQPUri {
            scheme: AMQPScheme::from_str(addr.scheme())
                .map_err(|_| ApplicationError::Unknown)?,
            authority: AMQPAuthority {
                userinfo: AMQPUserInfo {
                    username: username.to_string(),
                    password: password.to_string(),
                },
                host: addr.host_str().unwrap_or(DEFAULT_AMPQ_HOST).into(),
                port: addr.port().unwrap_or(DEFAULT_AMPQ_PORT),
            },
            vhost: DEFAULT_AMPQ_VHOST.to_string(),
            query: AMQPQueryString {
                channel_max: Some(10),
                ..Default::default()
            },
        };

        let recovery_config =
            RecoveryConfig::default().auto_recover_connection();
        let conn_config = ConnectionProperties::default()
            .with_connection_name("autha_maily_client".into())
            .with_experimental_recovery_config(recovery_config);
        let conn = Connection::connect_uri(uri, conn_config).await.catch()?;

        tracing::info!(%addr, "rabbitmq connected");

        tracing::debug!(queue = queue_name, "rabbitmq queue created");

        Ok(Self {
            queue_name: queue_name.to_string(),
            conn: Some(Arc::new(conn)),
        })
    }

    async fn create_channel(
        conn: Arc<Connection>,
        queue: &str,
    ) -> Result<Channel> {
        let channel = conn.create_channel().await.catch()?;
        channel
            .queue_declare(
                queue,
                QueueDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .catch()?;
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

    async fn publish<'a>(&self, message: Content<'a>) -> Result<()> {
        let Some(conn) = &self.conn else {
            return Ok(());
        };
        let channel =
            Self::create_channel(Arc::clone(conn), &self.queue_name).await?;

        let payload = Self::create_event(message);
        let payload = serde_json::to_vec(&payload).catch()?;

        channel
            .basic_publish(
                "",
                &self.queue_name,
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default()
                    .with_content_encoding(CONTENT_ENCODING.into())
                    .with_content_type(CONTENT_TYPE.into()),
            )
            .await
            .catch()?;

        Ok(())
    }
}

#[async_trait]
impl Mailer for RabbitMqMailer {
    async fn send_welcome(
        &self,
        email: &EmailAddress,
        locale: &str,
        username: &str,
    ) -> Result<()> {
        let message = Content {
            template: Template::Welcome,
            locale: Some(locale),
            to: email.as_str(),
            username,
        };

        self.publish(message).await
    }

    async fn send_login_notification(
        &self,
        email: &EmailAddress,
        locale: &str,
        username: &str,
    ) -> Result<()> {
        let message = Content {
            template: Template::DataUpdate,
            locale: Some(locale),
            to: email.as_str(),
            username,
        };

        self.publish(message).await
    }
}
