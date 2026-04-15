//! Application services implementing business logic.

pub const TOKEN_TYPE: &str = "Bearer";
const EXPIRES_IN: u64 = 900; // 15 minutes.

pub mod auth;
pub mod create_account;
pub mod get_user;
pub mod refresh_token;
pub mod status;
pub mod update_user;

pub use auth::*;
pub use create_account::*;
pub use get_user::*;
pub use refresh_token::*;
pub use status::*;
pub use update_user::*;
