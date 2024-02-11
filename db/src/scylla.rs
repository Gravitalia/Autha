use anyhow::{Context, Result};
use scylla::{
    frame::Compression, transport::session::PoolSize, Session, SessionBuilder,
};
use std::num::NonZeroUsize;

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

/// Define a structure to manage the Scylla connections.
#[derive(Debug)]
pub struct Scylla {
    /// Scylla connections to the cluster.
    pub connection: Session,
}

impl Scylla {
    /// Create tables on "accounts" keyspace.
    pub async fn create_tables(&self) -> Result<()> {
        for table in TABLES_TO_CREATE.iter() {
            self.connection
                .query(table.to_string(), &[])
                .await
                .context(format!("Failed to create table: {}", table))?;
        }

        for index in INDICES_TO_CREATE.iter() {
            self.connection
                .query(index.to_string(), &[])
                .await
                .context(format!("Failed to create index: {}", index))?;
        }

        Ok(())
    }

    /// Create a new scylla batch to perform mutliple requests.
    pub fn new_batch(&self) -> scylla::batch::Batch {
        scylla::batch::Batch::default()
    }
}

/// Initialize the connection for ScyllaDB or Apache Cassandra.
pub async fn init(
    hosts: Vec<String>,
    username: Option<String>,
    password: Option<String>,
    pool_size: usize,
) -> Result<Session> {
    let session = SessionBuilder::new()
        .known_nodes(hosts)
        .user(username.unwrap_or_default(), password.unwrap_or_default())
        .use_keyspace("accounts", true)
        .pool_size(PoolSize::PerHost(NonZeroUsize::new(pool_size).unwrap()))
        .compression(Some(Compression::Lz4))
        // Activate (true) if the application becomes bigger.
        // It should reduce latency if false, and increase write/read throughput if true.
        .write_coalescing(false)
        .build()
        .await?;

    Ok(session)
}
