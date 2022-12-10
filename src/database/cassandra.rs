use scylla::SessionBuilder;

use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use once_cell::sync::OnceCell;
static SESSION: OnceCell<scylla::Session> = OnceCell::new();

/// Start Cassandra session
pub async fn init() {
    let _session = SESSION.set(SessionBuilder::new().known_node("127.0.0.1:9042").build().await.unwrap());
}

/// Create tables in your Cassandra keyspace
pub async fn tables() {
    SESSION.get().unwrap().query("CREATE KEYSPACE IF NOT EXISTS accounts WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };", &[]).await.expect("Keyspace create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.users ( vanity text, email text, username text, avatar text, banner text, bio text, verified boolean, flags int, phone text, password text, birthdate text, deleted boolean, mfa_code text, oauth list<text>, PRIMARY KEY (vanity) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;", &[]).await.expect("accounts.users create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.security ( id text, user_id text, fingerprint text, ip text, country text, revoked boolean, type int, created_at timestamp, PRIMARY KEY (id) ) WITH caching = {'keys': 'ALL', 'rows_per_partition': 'ALL'} AND compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 172800 AND default_time_to_live = 15770000;", &[]).await.expect("accounts.security create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.bots ( id text, user_id text, client_secret text, ip text, username text, avatar text, bio text, flags int, deleted boolean, PRIMARY KEY (id, username) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;", &[]).await.expect("accounts.bots create error");
    SESSION.get().unwrap().query("CREATE INDEX IF NOT EXISTS ON accounts.users (email);", &[]).await.expect("second index (email) create error");
}

/// Create a user for account delegation
/// ```rust
/// create_user(&"realhinome".to_string(), "email@mail.com".to_string(), "Hinome".to_string(), "SuperPassword_123456".to_string(), None, None)
/// ```
pub async fn create_user(vanity: &String, email: String, username: String, password: String, phone: Option<String>, birthdate: Option<String>) {
    SESSION.get().unwrap().query("INSERT INTO accounts.users (vanity, email, username, password, phone, birthdate, flags, deleted, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (vanity, email, username, password, phone, birthdate, 0, false, false)).await.expect("Failed to create user");
}

/// Create a security token, used for email, phone verification and JWT centralization security
pub async fn create_security(vanity: String, _code: u8, fingerprint: String, ip: Option<String>, country: Option<String>) -> uuid::Uuid {
    let id: uuid::Uuid = Uuid::new_v4();

    SESSION.get().unwrap().query("INSERT INTO accounts.security (id, user_id, fingerprint, created_at, ip, country, revoked, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (id.to_string(), vanity, fingerprint, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64, ip, country, false, 0)).await.expect("Failed to create security token");
    id
}

pub async fn query(query: &'static str, params: Vec<String>) -> scylla::QueryResult {
    SESSION.get().unwrap().query(query, params).await.expect("Query error")
}

/// Update user data (public or authorization)
#[allow(clippy::type_complexity)]
pub async fn update_user(params: (String, Option<String>, Option<String>, Option<String>, Option<String>, String, String)) -> scylla::QueryResult {
    SESSION.get().unwrap().query("UPDATE accounts.users SET username = ?, avatar = ?, bio = ?, birthdate = ?, phone = ?, email = ? WHERE vanity = ?", params).await.expect("Query error")
}

/// Update the user password, need to be hashed first
pub async fn update_password(new_password: String, vanity: String) -> scylla::QueryResult {
    SESSION.get().unwrap().query("UPDATE accounts.users SET password = ? WHERE vanity = ?", (new_password, vanity)).await.expect("Query error")
}

/// Ban a user account, this will make a request in Central Moderation (Signaly)
pub async fn suspend(vanity: String) -> scylla::QueryResult {
    // Send request to mod center
    SESSION.get().unwrap().query("UPDATE accounts.users SET deleted = ?, verified = ? WHERE vanity = ?", (true, false, vanity.clone())).await.expect("Query error")

    // Get partition key
    //SESSION.get().unwrap().query("UPDATE accounts.bots SET deleted = ?, ip = ? WHERE user_id = ?", (true, "", vanity)).await.expect("Query error");
    //SESSION.get().unwrap().query("UPDATE accounts.security SET revoked = ?, fingerprint = ? WHERE user_id = ?", (true, "", vanity.clone())).await.expect("Query error")
}