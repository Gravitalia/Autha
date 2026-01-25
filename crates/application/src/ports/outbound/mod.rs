//! These traits define what the application needs from the outside world.

pub mod account;
pub mod clock;
pub mod crypto;
pub mod key;
pub mod ldap;
pub mod mailer;
pub mod telemetry;
pub mod token;

pub use account::*;
pub use clock::*;
pub use crypto::*;
pub use key::*;
pub use ldap::*;
pub use mailer::*;
pub use telemetry::*;
pub use token::*;
