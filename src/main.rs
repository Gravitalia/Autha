mod database;
mod helpers;
mod model;

use crate::database::scylla::ScyllaManager;
use warp::Filter;

#[tokio::main]
async fn main() {
    // Set logger with Fern.
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {}] {}",
                helpers::format::format_rfc3339(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs()
                ),
                record.level(),
                message
            ))
        })
        .level(if cfg!(debug_assertions) {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Info
        })
        .level_for("hyper", log::LevelFilter::Error)
        .level_for("warp_server", log::LevelFilter::Info)
        .chain(std::io::stdout())
        .apply()
        .unwrap();

    // Read configuration file.
    let config = helpers::config::read();

    // Initialize databases.
    let scylladb = match database::scylla::init(config.clone()).await {
        Ok(pool) => {
            log::info!("Cassandra/ScyllaDB connection created successfully.");

            database::scylla::Scylla { connection: pool }
        }
        Err(error) => {
            // A connection failure renders the entire API unstable and unusable.
            log::error!(
                "Cannot initialize Apache Cassandra or ScyllaDB connection: {}",
                error
            );
            std::process::exit(0);
        }
    };

    let memcached_pool = match database::memcached::init(&config) {
        Ok(pool) => {
            log::info!("Memcached pool connection created successfully.");

            database::memcached::MemPool {
                connection: Some(pool),
            }
        }
        Err(error) => {
            // In the event that establishing a connections pool encounters any difficulties, it will be duly logged.
            // Such a scenario might lead to suboptimal performance in specific requests.
            // It makes also impossible to create temporary code, for instance, for OAuth requests.
            log::warn!(
                "Cannot initialize Memcached pool, this could result in poor performance: {}",
                error
            );

            database::memcached::MemPool { connection: None }
        }
    };

    // Create needed tables.
    match scylladb.create_tables().await {
        Ok(_) => {
            log::trace!("Successfully created tables, if they didn't exist.");
        }
        Err(error) => {
            log::error!("Failed to create tables: {}", error)
        }
    };

    warp::serve(
        warp::any()
            .and(warp::options())
            .map(|| "OK")
            .or(warp::head().map(|| "OK")),
    )
    .run(([0, 0, 0, 0], config.port))
    .await;
}
