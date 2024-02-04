use anyhow::Result;
use db::libscylla::prepared_statement::PreparedStatement;
use std::sync::OnceLock;

pub static CREATE_USER: OnceLock<PreparedStatement> = OnceLock::new();
pub static CREATE_TOKEN: OnceLock<PreparedStatement> = OnceLock::new();
pub static CREATE_SALT: OnceLock<PreparedStatement> = OnceLock::new();
pub static CREATE_OAUTH: OnceLock<PreparedStatement> = OnceLock::new();

/// Init prepared query to properly balance.
/// This should improve the performance of queries, as well as providing better balancing.
pub async fn init(scylla: &std::sync::Arc<db::scylla::Scylla>) -> Result<()> {
    // Create user.
    let create_query = scylla
    .connection
    .prepare(
        "INSERT INTO accounts.users (vanity, email, username, password, locale, phone, birthdate, flags, deleted, verified, expire_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, false, false, 0)"
    )
    .await?;
    CREATE_USER.get_or_init(|| create_query);

    // Create token.
    let create_token = scylla
    .connection
    .prepare(
        "INSERT INTO accounts.tokens (id, user_id, ip, date, deleted) VALUES (?, ?, ?, ?, false)"
    )
    .await?;
    CREATE_TOKEN.get_or_init(|| create_token);

    // Create salt.
    let create_salt = scylla
        .connection
        .prepare("INSERT INTO accounts.salts (id, salt) VALUES (?, ?)")
        .await?;
    CREATE_SALT.get_or_init(|| create_salt);

    // Create oauth.
    let create_oauth = scylla
        .connection
        .prepare(
            "INSERT INTO accounts.oauth (id, user_id, bot_id, scope, deleted) VALUES (?, ?, ?, ?, ?)"
        )
        .await?;
    CREATE_OAUTH.get_or_init(|| create_oauth);

    Ok(())
}
