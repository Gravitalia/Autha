//! Interface for email operations.

use async_trait::async_trait;
use domain::identity::email::EmailAddress;

use crate::error::Result;

/// Port for sending emails.
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Send a welcome email to a new user.
    async fn send_welcome(
        &self,
        email: &EmailAddress,
        locale: &str,
        username: &str,
    ) -> Result<()>;

    /// Send a login notification email.
    async fn send_login_notification(
        &self,
        email: &EmailAddress,
        locale: &str,
        username: &str,
    ) -> Result<()>;
}
