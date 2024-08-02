use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

/// A message transmitted to all departments by a broker like Kafka.
#[derive(Serialize, Debug)]
pub struct Message<D>
where
    D: Serialize + DeserializeOwned + Debug,
{
    /// Unique identifier for the event.
    pub id: String,
    /// Content type of the event data.
    /// Should be application/json.
    pub datacontenttype: String,
    /// Data associated with the event.
    pub data: D,
    /// Source of the event.
    pub source: String,
    /// CloudEvents specification version.
    /// Should be 1.0
    pub specversion: String,
    /// Timestamp of when the event occurred in RFC 3339 format.
    pub time: Option<String>,
    /// Type of the event.
    pub r#type: String,
}
