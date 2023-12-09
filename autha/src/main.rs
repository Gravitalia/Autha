mod helpers;
mod model;
mod router;

#[macro_use]
extern crate lazy_static;
use db::scylla::ScyllaManager;
use std::sync::Arc;
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
    let scylladb = match db::scylla::init(
        config.database.scylla.hosts,
        config.database.scylla.username,
        config.database.scylla.password,
        config
            .database
            .scylla
            .pool_size
            .try_into()
            .unwrap_or_default(),
    )
    .await
    {
        Ok(pool) => {
            log::info!("Cassandra/ScyllaDB connection created successfully.");

            Arc::new(db::scylla::Scylla { connection: pool })
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

    let memcached_pool = match db::memcache::init(
        config.database.memcached.hosts,
        config.database.memcached.pool_size,
    ) {
        Ok(pool) => {
            log::info!("Memcached pool connection created successfully.");

            db::memcache::MemcachePool {
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

            db::memcache::MemcachePool { connection: None }
        }
    };

    // Create needed tables.
    match scylladb.create_tables().await {
        Ok(_) => {
            log::trace!("Successfully created tables, if they didn't exist.");
        }
        Err(error) => {
            log::error!("Failed to create tables: {}", error);
        }
    };

    let create_route = warp::path("create")
        .and(warp::post())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::body::json())
        .and(warp::header::optional::<String>("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(router::create_user);

    let login_route = warp::path("login")
        .and(warp::post())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::body::json())
        .and(warp::header::optional::<String>("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(router::login_user);

    let get_user_route = warp::path!("users" / String)
        .and(warp::get())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::header::optional::<String>("authorization"))
        .and_then(router::get_user);

    warp::serve(
        warp::any()
            .and(warp::options())
            .map(|| "OK")
            .or(warp::head().map(|| "OK").or(create_route).or(login_route).or(get_user_route)),
    )
    .run(([0, 0, 0, 0], config.port))
    .await;
}
