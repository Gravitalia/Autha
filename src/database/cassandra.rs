use cdrs_tokio::cluster::session::{TcpSessionBuilder, SessionBuilder};
use cdrs_tokio::cluster::NodeTcpConfigBuilder;
use cdrs_tokio::load_balancing::RoundRobinLoadBalancingStrategy;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use once_cell::sync::OnceCell;
static CLIENT: OnceCell<cdrs_tokio::cluster::NodeTcpConfig> = OnceCell::new();
static SESSION: OnceCell<cdrs_tokio::cluster::session::Session<cdrs_tokio::transport::TransportTcp, cdrs_tokio::cluster::TcpConnectionManager, cdrs_tokio::load_balancing::RoundRobinLoadBalancingStrategy<cdrs_tokio::transport::TransportTcp, cdrs_tokio::cluster::TcpConnectionManager>>> = OnceCell::new();

pub async fn init() {
    let _db = CLIENT.set(NodeTcpConfigBuilder::new().with_contact_point("127.0.0.1:9042".into()).build().await.unwrap());
    let _sess = SESSION.set(TcpSessionBuilder::new(RoundRobinLoadBalancingStrategy::new(), CLIENT.get().cloned().unwrap()).build());
}

pub async fn tables() {
    SESSION.get().unwrap().query("CREATE KEYSPACE IF NOT EXISTS accounts WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };").await.expect("Keyspace create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.users ( vanity text, email text, username text, avatar text, banner text, bio text, verified boolean, flags int, phone text, password text, birthdate text, deleted boolean, mfa_code text, oauth list<text>, PRIMARY KEY (vanity, email) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").await.expect("accounts.users create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.security ( id text, user_id text, fingerprint text, ip text, country text, revoked boolean, type int, created_at timestamp, PRIMARY KEY (id) ) WITH caching = {'keys': 'ALL', 'rows_per_partition': 'ALL'} AND compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 172800 AND default_time_to_live = 15770000;").await.expect("accounts.security create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.bots ( id text, user_id text, client_secret text, ip text, username text, avatar text, bio text, flags int, deleted boolean, PRIMARY KEY (id, username) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").await.expect("accounts.bots create error");
    SESSION.get().unwrap().query("CREATE INDEX IF NOT EXISTS ON accounts.users (email);").await.expect("second index (email) create error");
}

pub async fn create_user(vanity: String, email: String, username: String, password: String, phone: Option<String>, birthdate: Option<String>) {
    let mut user: Vec<String> = vec![vanity, email, username, password];
    if phone.is_some() { user.push(phone.unwrap()); } else { user.push("".to_string()); }
    if birthdate.is_some() { user.push(birthdate.unwrap()); } else { user.push("".to_string()); }

    SESSION.get().unwrap().query_with_values(format!("INSERT INTO accounts.users (vanity, email, username, password, phone, birthdate, flags, deleted) VALUES (?, ?, ?, ?, ?, ?, {}, {})", 0, false), user).await.expect("Failed to create user");
}

pub async fn create_security(vanity: String, code: u8, fingerprint: String, ip: Option<String>, country: Option<String>) -> uuid::Uuid {
    let id: uuid::Uuid = Uuid::new_v4();
    let mut data: Vec<String> = vec![id.to_string(), vanity, fingerprint];
    if ip.is_some() { data.push(ip.unwrap()); } else { data.push("".to_string()); }
    if country.is_some() { data.push(country.unwrap()); } else { data.push("".to_string()); }

    SESSION.get().unwrap().query_with_values(format!("INSERT INTO accounts.security (id, user_id, fingerprint, created_at, ip, country, revoked, type) VALUES (?, ?, ?, {}, ?, ?, {}, {})", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(), false, code), data).await.expect("Failed to create security token");
    id
}

pub async fn query(query: &'static str, params: Vec<String>) -> cdrs_tokio::frame::Frame {
    SESSION.get().unwrap().query_with_values(query, params).await.expect("Query error")
}