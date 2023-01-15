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
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.users ( vanity text, email text, username text, avatar text, banner text, bio text, verified boolean, flags int, phone text, password text, birthdate text, deleted boolean, mfa_code text, oauth list<text>, PRIMARY KEY (vanity, email) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").expect("accounts.users create error");
    SESSION.get().unwrap().query("CREATE TABLE IF NOT EXISTS accounts.bots ( id text, user_id text, client_secret text, ip text, username text, avatar text, bio text, flags int, deleted boolean, PRIMARY KEY (id, username) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").expect("accounts.bots create error");
}

/// Make a query to cassandra
pub fn query(query: &'static str, params: Vec<String>) -> std::result::Result<cdrs::frame::Frame, cdrs::error::Error> {
    SESSION.get().unwrap().query_with_values(query, params)
}