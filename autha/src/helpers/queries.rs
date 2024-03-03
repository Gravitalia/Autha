use db::libscylla::{
    prepared_statement::PreparedStatement, transport::errors::QueryError,
};
use db::scylla::Scylla;
use std::sync::{Arc, OnceLock};

pub static CREATE_USER: OnceLock<PreparedStatement> = OnceLock::new();
pub static CREATE_TOKEN: OnceLock<PreparedStatement> = OnceLock::new();
pub static CREATE_SALT: OnceLock<PreparedStatement> = OnceLock::new();
pub static CREATE_OAUTH: OnceLock<PreparedStatement> = OnceLock::new();
pub static GET_USER: OnceLock<PreparedStatement> = OnceLock::new();
pub static GET_USER_REFRESH_TOKEN: OnceLock<PreparedStatement> =
    OnceLock::new();

/// Init prepared query to properly balance.
/// This should improve the performance of queries, as well as providing better balancing.
pub async fn init(scylla: &Arc<Scylla>) -> Result<(), QueryError> {
    let prepared_queries = [
        ("INSERT INTO accounts.users (vanity, email, username, password, locale, phone, birthdate, flags, deleted, verified, expire_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, false, false, 0)", &CREATE_USER),
        ("INSERT INTO accounts.tokens (id, user_id, ip, date, deleted) VALUES (?, ?, ?, ?, false)", &CREATE_TOKEN),
        ("INSERT INTO accounts.salts (id, salt) VALUES (?, ?)", &CREATE_SALT),
        ("INSERT INTO accounts.oauth (id, user_id, bot_id, scope, deleted) VALUES (?, ?, ?, ?, ?) USING TTL 5184000", &CREATE_OAUTH),
        ("SELECT username, vanity, avatar, bio, email, birthdate, phone, verified, deleted, flags FROM accounts.users WHERE vanity = ?", &GET_USER),
        ("SELECT id, user_id, bot_id, scope, deleted FROM accounts.oauth WHERE user_id = ?", &GET_USER_REFRESH_TOKEN)
    ];

    for (query, lock) in &prepared_queries {
        let prepared_query =
            scylla.connection.prepare(query.to_string()).await?;

        lock.get_or_init(|| prepared_query);
    }

    Ok(())
}

/// Create tables on "accounts" keyspace.
pub async fn create_tables(scylla: &Arc<Scylla>) -> Result<(), QueryError> {
    let tables = [
        r#"
                CREATE TABLE IF NOT EXISTS users (
                    vanity TEXT,
                    email TEXT,
                    username TEXT,
                    avatar TEXT,
                    banner TEXT,
                    bio TEXT,
                    verified BOOLEAN,
                    flags INT,
                    locale TEXT,
                    phone TEXT,
                    password TEXT,
                    birthdate TEXT,
                    deleted BOOLEAN,
                    mfa_code TEXT,
                    expire_at TIMESTAMP,
                    PRIMARY KEY (vanity) );
            "#,
        r#"
                CREATE TABLE IF NOT EXISTS accounts.bots (
                    id TEXT,
                    user_id TEXT,
                    client_secret TEXT,
                    username TEXT,
                    avatar TEXT,
                    bio TEXT,
                    redirect_url SET<TEXT>,
                    flags INT,
                    deleted BOOLEAN,
                    PRIMARY KEY (id) )
                    WITH gc_grace_seconds = 604800;
            "#,
        r#"
                CREATE TABLE IF NOT EXISTS accounts.oauth (
                    id TEXT,
                    user_id TEXT,
                    bot_id TEXT,
                    scope SET<TEXT>,
                    deleted BOOLEAN,
                    PRIMARY KEY (id) );
            "#,
        r#"
                CREATE TABLE IF NOT EXISTS accounts.tokens (
                    id TEXT,
                    user_id TEXT,
                    ip TEXT,
                    date TIMESTAMP,
                    deleted BOOLEAN,
                    PRIMARY KEY (id) )
                    WITH default_time_to_live = 1210000
                    AND gc_grace_seconds = 604800;
            "#,
        r#"
                CREATE TABLE IF NOT EXISTS accounts.salts (
                    id TEXT,
                    salt TEXT,
                    PRIMARY KEY (id) );
            "#,
    ];

    // Define all the CQL queries for creating indexes.
    let indexes: [&str; 4] = [
        "CREATE INDEX IF NOT EXISTS ON accounts.users ( email );",
        "CREATE INDEX IF NOT EXISTS ON accounts.users ( expire_at );",
        "CREATE INDEX IF NOT EXISTS ON accounts.oauth ( user_id );",
        "CREATE INDEX IF NOT EXISTS ON accounts.tokens ( user_id );",
    ];

    for table in tables.iter() {
        scylla.connection.query(*table, &[]).await?;
    }

    for index in indexes.iter() {
        scylla.connection.query(*index, &[]).await?;
    }

    Ok(())
}
