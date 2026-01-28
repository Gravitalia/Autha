//! Public key repository port.

use async_trait::async_trait;
use domain::identity::user::User;
use domain::key::pem::PemFingerprint;
use domain::key::public_key::Key;

use crate::error::Result;

/// Port for public key operations.
#[async_trait]
pub trait KeyRepository: Send + Sync {
    /// Create a new [`Key`] and link it to [`User`].
    async fn create_and_link(&self, key: &Key, user: &User) -> Result<()>;

    /// Delete and unlink a key.
    async fn delete(&self, id: &PemFingerprint) -> Result<()>;
}
