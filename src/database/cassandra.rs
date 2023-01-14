use cdrs_tokio::cluster::{TcpConnectionManager, NodeTcpConfigBuilder, session::{TcpSessionBuilder, SessionBuilder, Session}};
use cdrs_tokio::load_balancing::RoundRobinLoadBalancingStrategy;
use cdrs_tokio::transport::TransportTcp;

pub async fn init() -> Session<TransportTcp, TcpConnectionManager, RoundRobinLoadBalancingStrategy<TransportTcp, TcpConnectionManager>> {
    let cluster_config = NodeTcpConfigBuilder::new()
        .with_contact_point("127.0.0.1:9042".into())
        .build()
        .await
        .unwrap();

    TcpSessionBuilder::new(RoundRobinLoadBalancingStrategy::new(), cluster_config)
        .build()
        .unwrap()
}

pub async fn create_tables(session: &Session<TransportTcp, TcpConnectionManager, RoundRobinLoadBalancingStrategy<TransportTcp, TcpConnectionManager>>) {
    session.query("CREATE KEYSPACE IF NOT EXISTS accounts WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };").await.expect("Keyspace create error");
    session.query("CREATE TABLE IF NOT EXISTS accounts.users ( vanity text, email text, username text, avatar text, banner text, bio text, verified boolean, flags int, phone text, password text, birthdate text, deleted boolean, mfa_code text, oauth list<text>, PRIMARY KEY (vanity, email) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").await.expect("accounts.users create error");
    session.query("CREATE TABLE IF NOT EXISTS accounts.bots ( id text, user_id text, client_secret text, ip text, username text, avatar text, bio text, flags int, deleted boolean, PRIMARY KEY (id, username) ) WITH compression = {'chunk_length_in_kb': '64', 'class': 'org.apache.cassandra.io.compress.ZstdCompressor'} AND gc_grace_seconds = 864000;").await.expect("accounts.bots create error");
}