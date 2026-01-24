//! Identity port between the domain layer and the data mapping layer.

use crate::{error::Result, identity::{id::UserId, user::User}};

/// Port for user persistence.
#[async_trait::async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>>;
    async fn find_by_email(&self, hash: &str) -> Result<Option<User>>;
    async fn create(&self, user: &User) -> Result<()>;
    async fn update(&self, user: &User) -> Result<()>;
    async fn delete(&self, id: &UserId) -> Result<()>;
}
