use scylla::{
    frame::Compression,
    transport::{errors::NewSessionError, session::PoolSize},
    Session, SessionBuilder,
};
use std::num::NonZeroUsize;

/// Define a structure to manage the Scylla connections.
#[derive(Debug)]
pub struct Scylla {
    /// Scylla connections to the cluster.
    pub connection: Session,
}

/// Initialize the connection for ScyllaDB or Apache Cassandra.
pub async fn init(
    hosts: Vec<String>,
    username: Option<String>,
    password: Option<String>,
    pool_size: usize,
) -> Result<Session, NewSessionError> {
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
