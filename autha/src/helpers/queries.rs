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

// Define constants for table creation and queries.
const CREATE_USERS_TABLE: &str = r#"
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
"#;
const CREATE_BOTS_TABLE: &str = r#"
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
"#;
const CREATE_OAUTH_TABLE: &str = r#"
    CREATE TABLE IF NOT EXISTS accounts.oauth (
        id TEXT,
        user_id TEXT,
        bot_id TEXT,
        scope SET<TEXT>,
        deleted BOOLEAN,
        PRIMARY KEY (id) );
"#;
const CREATE_TOKENS_TABLE: &str = r#"
    CREATE TABLE IF NOT EXISTS accounts.tokens (
        id TEXT,
        user_id TEXT,
        ip TEXT,
        date TIMESTAMP,
        deleted BOOLEAN,
        PRIMARY KEY (id) )
        WITH default_time_to_live = 1210000
        AND gc_grace_seconds = 604800;
"#;
const CREATE_SALTS_TABLE: &str = r#"
    CREATE TABLE IF NOT EXISTS accounts.salts (
        id TEXT,
        salt TEXT,
        PRIMARY KEY (id) );
"#;
const CREATE_USERS_INDEX_EMAIL: &str =
    "CREATE INDEX IF NOT EXISTS ON accounts.users ( email );";
const CREATE_USERS_INDEX_EXPIRE_AT: &str =
    "CREATE INDEX IF NOT EXISTS ON accounts.users ( expire_at );";
const CREATE_OAUTH_INDEX_USER_ID: &str =
    "CREATE INDEX IF NOT EXISTS ON accounts.oauth ( user_id );";
const CREATE_TOKENS_INDEX_USER_ID: &str =
    "CREATE INDEX IF NOT EXISTS ON accounts.tokens ( user_id );";

/// Define all the CQL queries for creating tables.
const TABLES_TO_CREATE: [&str; 5] = [
    CREATE_USERS_TABLE,
    CREATE_BOTS_TABLE,
    CREATE_OAUTH_TABLE,
    CREATE_TOKENS_TABLE,
    CREATE_SALTS_TABLE,
];

/// Define all the CQL queries for creating indexes.
const INDICES_TO_CREATE: [&str; 4] = [
    CREATE_USERS_INDEX_EMAIL,
    CREATE_USERS_INDEX_EXPIRE_AT,
    CREATE_OAUTH_INDEX_USER_ID,
    CREATE_TOKENS_INDEX_USER_ID,
];

/// Init prepared query to properly balance.
/// This should improve the performance of queries, as well as providing better balancing.
pub async fn init(scylla: &Arc<Scylla>) -> Result<(), QueryError> {
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

    // Get user.
    let get_user = scylla
            .connection
            .prepare(
                "SELECT username, vanity, avatar, bio, email, birthdate, phone, verified, deleted, flags FROM accounts.users WHERE vanity = ?"
            )
            .await?;
    GET_USER.get_or_init(|| get_user);

    Ok(())
}

/// Create tables on "accounts" keyspace.
pub async fn create_tables(scylla: &Arc<Scylla>) -> Result<(), QueryError> {
    for table in TABLES_TO_CREATE.iter() {
        scylla.connection.query(table.to_string(), &[]).await?;
    }

    for index in INDICES_TO_CREATE.iter() {
        scylla.connection.query(index.to_string(), &[]).await?;
    }

    Ok(())
}
