use cdrs::authenticators::NoneAuthenticator;
use cdrs::cluster::session::{new as new_session, Session};
use cdrs::cluster::{ClusterTcpConfig, NodeTcpConfigBuilder, TcpConnectionPool};
use cdrs::load_balancing::RoundRobin;
use cdrs::query::*;

type CurrentSession = Session<RoundRobin<TcpConnectionPool<NoneAuthenticator>>>;
use once_cell::sync::OnceCell;
static SESSION: OnceCell<CurrentSession> = OnceCell::new();

/// Init cassandra session
pub fn init() {
    let _ = SESSION.set(new_session(&ClusterTcpConfig(vec![NodeTcpConfigBuilder::new("127.0.0.1:9042", NoneAuthenticator {}).build()]), RoundRobin::new()).expect("session should be created"));
}

/// Create tables in cassandra keyspace if not exists
pub fn create_tables() {
    SESSION.get().unwrap().query("CREATE KEYSPACE IF NOT EXISTS accounts WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };").expect("Keyspace create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.users ( vanity text, email text, username text, avatar text, banner text, bio text, verified boolean, flags int, phone text, password text, birthdate text, deleted boolean, mfa_code text, PRIMARY KEY (vanity) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").expect("accounts.users create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.bots ( id text, user_id text, client_secret text, username text, avatar text, bio text, redirect_url set<text>, flags int, deleted boolean, PRIMARY KEY (id) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").expect("accounts.bots create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.oauth ( id text, user_id text, bot_id text, ip text, scope set<text>, deleted boolean, PRIMARY KEY (id) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 0;").expect("accounts.oauth create error");
    SESSION.get().unwrap().query("CREATE INDEX IF NOT EXISTS ON accounts.users (email);").expect("second index (email) create error");
    SESSION.get().unwrap().query("CREATE INDEX IF NOT EXISTS ON accounts.oauth (user_id);").expect("second index (user_id) create error");
}

/// Make a query to cassandra
pub fn query(query: &'static str, params: Vec<String>) -> std::result::Result<cdrs::frame::Frame, cdrs::error::Error> {
    SESSION.get().unwrap().query_with_values(query, params)
}

/// Create a user for account delegation
/// ```rust
/// create_user(&"realhinome".to_string(), "email@mail.com".to_string(), "Hinome".to_string(), "SuperPassword_123456".to_string(), None, None)
/// ```
pub fn create_user(vanity: &String, email: String, username: String, password: String, phone: Option<String>, birthdate: Option<String>) -> Result<(), cdrs::error::Error> {
    let mut user: Vec<String> = vec![vanity.to_string(), email, username, password];
    if let Some(x) = phone { user.push(x); } else { user.push("".to_string()); }
    if let Some(y) = birthdate { user.push(y); } else { user.push("".to_string()); }

    SESSION.get().unwrap().query_with_values(format!("INSERT INTO accounts.users (vanity, email, username, password, phone, birthdate, flags, deleted) VALUES (?, ?, ?, ?, ?, ?, {}, {})", 0, false), user)?;

    Ok(())
}