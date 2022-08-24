use cdrs_tokio::cluster::session::{TcpSessionBuilder, SessionBuilder};
use cdrs_tokio::cluster::NodeTcpConfigBuilder;
use cdrs_tokio::load_balancing::RoundRobinLoadBalancingStrategy;
use once_cell::sync::OnceCell;
static CLIENT: OnceCell<cdrs_tokio::cluster::NodeTcpConfig> = OnceCell::new();
static SESSION: OnceCell<cdrs_tokio::cluster::session::Session<cdrs_tokio::transport::TransportTcp, cdrs_tokio::cluster::TcpConnectionManager, cdrs_tokio::load_balancing::RoundRobinLoadBalancingStrategy<cdrs_tokio::transport::TransportTcp, cdrs_tokio::cluster::TcpConnectionManager>>> = OnceCell::new();

pub async fn init() {
    let _db =  CLIENT.set(NodeTcpConfigBuilder::new().with_contact_point("127.0.0.1:9042".into()).build().await.unwrap());
    let _sess = SESSION.set(TcpSessionBuilder::new(RoundRobinLoadBalancingStrategy::new(), CLIENT.get().cloned().unwrap()).build());
}

pub async fn tables() {
    SESSION.get().unwrap().query("CREATE KEYSPACE IF NOT EXISTS accounts WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };").await.expect("Keyspace create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.users ( vanity text, email text, username text, avatar text, banner text, bio text, verified boolean, flags int, ip text, phone text, password text, birthdate text, deleted boolean, mfa_code text, oauth list<text>, PRIMARY KEY (vanity, email) ) WITH bloom_filter_fp_chance = 0.1 AND caching = {'keys': 'ALL', 'rows_per_partition': 'NONE'} AND comment = '' AND compaction = {'class': 'org.apache.cassandra.db.compaction.LeveledCompactionStrategy'} AND compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND crc_check_chance = 1.0 AND default_time_to_live = 0 AND gc_grace_seconds = 864000 AND max_index_interval = 2048 AND memtable_flush_period_in_ms = 0 AND min_index_interval = 128 AND speculative_retry = '99PERCENTILE';").await.expect("accounts.users create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.security ( id text, user_id text, fingerprint text, ip text, country text, revoked boolean, type int, PRIMARY KEY (id) ) WITH bloom_filter_fp_chance = 0.1 AND caching = {'keys': 'ALL', 'rows_per_partition': 'NONE'} AND comment = '' AND compaction = {'class': 'org.apache.cassandra.db.compaction.LeveledCompactionStrategy'} AND compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND crc_check_chance = 1.0 AND default_time_to_live = 0 AND gc_grace_seconds = 172800 AND max_index_interval = 2048 AND memtable_flush_period_in_ms = 0 AND min_index_interval = 128 AND speculative_retry = '99PERCENTILE';").await.expect("accounts.security create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.bots ( id text, user_id text, client_secret text, ip text, country text, username text, avatar text, bio text, flags int, deleted boolean, PRIMARY KEY (id, username) ) WITH bloom_filter_fp_chance = 0.1 AND caching = {'keys': 'ALL', 'rows_per_partition': 'NONE'} AND comment = '' AND compaction = {'class': 'org.apache.cassandra.db.compaction.LeveledCompactionStrategy'} AND compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND crc_check_chance = 1.0 AND default_time_to_live = 0 AND gc_grace_seconds = 259200 AND max_index_interval = 2048 AND memtable_flush_period_in_ms = 0 AND min_index_interval = 128 AND speculative_retry = '99PERCENTILE';").await.expect("accounts.bots create error");
}

pub async fn create_user(vanity: String, email: String, username: String, password: String, phone: Option<String>, birthdate: Option<String>) -> String {
    let mut user: Vec<String> = vec![vanity, email, username, "".to_string(), password];
    if phone.is_some() {
        user.push(phone.unwrap());
    } else {
        user.push("".to_string());
    }
    if birthdate.is_some() {
        user.push(birthdate.unwrap());
    } else {
        user.push("".to_string());
    }

    SESSION.get().unwrap().query_with_values("INSERT INTO accounts.users (vanity, email, username, ip, password, phone, birthdate) VALUES (?, ?, ?, ?, ?, ?, ?)", user).await.expect("Failed to create user");

    return "ok".to_string();
}