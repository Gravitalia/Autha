use std::sync::Arc;

use rand::RngCore;
use sqlx::{Pool, Postgres, Transaction};

use crate::crypto::Crypto;
use crate::error::Result;
use crate::user::{User, UserRepository};

pub const TOKEN_LENGTH: u64 = 64;

/// User manager.
#[derive(Clone)]
pub struct UserService {
    pub repo: UserRepository,
    pub crypto: Arc<Crypto>,
    pub data: User,
}

impl UserService {
    /// Create a new [`UserService`].
    pub fn new(user: User, pool: Pool<Postgres>, crypto: Arc<Crypto>) -> Self {
        Self {
            data: user,
            repo: UserRepository::new(pool),
            crypto,
        }
    }

    /// Create builded user.
    ///
    /// Hash password and encrypt email.
    pub async fn create_user(mut self) -> Result<Self> {
        self.data.email_hash = self.crypto.hasher.digest(self.data.email_hash);
        self.data.email_cipher = self
            .crypto
            .symmetric
            .encrypt_and_hex(self.data.email_cipher)?;

        self.repo.insert(&self.data).await?;
        Ok(self)
    }

    /// Find current user using `id` field.
    pub async fn find_by_id(mut self) -> Result<Self> {
        self.data = self.repo.find_by_id(&self.data.id).await?;
        Ok(self)
    }

    /// Find current user using `email` field.
    pub async fn find_by_email(mut self) -> Result<Self> {
        self.data = self.repo.find_by_email(&self.data.email_hash).await?;
        Ok(self)
    }

    /// Generate a new 15-day (refresh token) to user.
    pub async fn generate_token(&self) -> Result<String> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);

        self.repo
            .insert_token(&token, &self.data.id, self.data.ip.clone())
            .await?;
        Ok(token)
    }

    /// Update current user.
    pub async fn update(
        &self,
        tx: Transaction<'static, Postgres>,
    ) -> Result<()> {
        self.repo.update(&self.data, tx).await
    }

    /// Delete current user with 30-day retention.
    pub async fn delete(&self) -> Result<()> {
        self.repo.delete(&self.data.id).await
    }
}
