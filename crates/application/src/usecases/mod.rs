//! Application services implementing business logic.

pub const TOKEN_TYPE: &str = "Brearer";
const EXPIRES_IN: u64 = 900; // 15 minutes.

pub mod auth;
pub mod create_account;

pub use auth::*;
pub use create_account::*;
