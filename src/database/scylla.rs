use anyhow::Result;
use async_trait::async_trait;
use scylla::{frame::Compression, transport::session::PoolSize, Session, SessionBuilder};
use std::num::NonZeroUsize;

// Define constants for table creation and queries
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
        phone TEXT,
        password TEXT,
        birthdate TEXT,
        deleted BOOLEAN,
        mfa_code TEXT,
        expire_at TIMESTAMP,
        PRIMARY KEY (vanity) )
        WITH cdc = TRUE;
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
        expire_at TIMESTAMP,
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
const CREATE_USERS_INDEX_EMAIL: &str = "CREATE INDEX IF NOT EXISTS ON accounts.users ( email );";
const CREATE_USERS_INDEX_EXPIRE_AT: &str =
    "CREATE INDEX IF NOT EXISTS ON accounts.users ( expire_at );";
const CREATE_OAUTH_INDEX_USER_ID: &str =
    "CREATE INDEX IF NOT EXISTS ON accounts.oauth ( user_id );";
const CREATE_TOKENS_INDEX_USER_ID: &str =
    "CREATE INDEX IF NOT EXISTS ON accounts.tokens ( user_id );";

/// Define a structure to manage the Scylla connections.
#[derive(Debug)]
pub struct Scylla {
    pub connection: Session,
}

/// Define a trait for the ScyllaManager with methods to interact with Scylla or Cassandra.
#[async_trait]
pub trait ScyllaManager {
    /// Create every needed tables, if not exists.
    async fn create_tables(&self) -> Result<()>;
}

#[async_trait]
impl ScyllaManager for Scylla {
    async fn create_tables(&self) -> Result<()> {
        self.connection
            .query(CREATE_USERS_TABLE, &[])
            .await
            .expect("accounts.users creation error");
        self.connection
            .query(CREATE_BOTS_TABLE, &[])
            .await
            .expect("accounts.bots creation error");
        self.connection
            .query(CREATE_OAUTH_TABLE, &[])
            .await
            .expect("accounts.oauth creation error");
        self.connection
            .query(CREATE_TOKENS_TABLE, &[])
            .await
            .expect("accounts.tokens creation error");
        self.connection
            .query(CREATE_SALTS_TABLE, &[])
            .await
            .expect("accounts.slats creation error");
        self.connection
            .query(CREATE_USERS_INDEX_EMAIL, &[])
            .await
            .expect("second index (email");
        self.connection
            .query(CREATE_USERS_INDEX_EXPIRE_AT, &[])
            .await
            .expect("second index (expire_at");
        self.connection
            .query(CREATE_OAUTH_INDEX_USER_ID, &[])
            .await
            .expect("second index (user_id");
        self.connection
            .query(CREATE_TOKENS_INDEX_USER_ID, &[])
            .await
            .expect("second index (user_id");

        Ok(())
    }
}

/// Initialize the connection for ScyllaDB or Apache Cassandra.
pub async fn init(config: crate::model::config::Config) -> Result<Session> {
    let session = SessionBuilder::new()
        .known_nodes(config.database.scylla.hosts)
        .user(
            config.database.scylla.username.unwrap_or_default(),
            config.database.scylla.password.unwrap_or_default(),
        )
        .use_keyspace("accounts", true)
        .pool_size(PoolSize::PerHost(
            NonZeroUsize::new(config.database.scylla.pool_size.try_into().unwrap()).unwrap(),
        ))
        .compression(Some(Compression::Lz4))
        // Activate (true) if the application becomes bigger.
        // It should reduce latency if false, and increase write/read throughput if true.
        .write_coalescing(false)
        .build()
        .await?;

    Ok(session)
}
