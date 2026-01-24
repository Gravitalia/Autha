//! Public key port between the domain layer and the data mapping layer.

use crate::error::Result;
use crate::key::public_key::Key;

/// Port for public key.
#[async_trait::async_trait]
pub trait KeyRepository: Send + Sync {
    async fn create(&self, key: &Key) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
}
