mod helpers;
mod model;
mod router;

#[macro_use]
extern crate lazy_static;
use db::scylla::ScyllaManager;
use std::error::Error;
use std::sync::Arc;
use warp::Filter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
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
        .apply()?;

    // Read configuration file.
    let config = helpers::config::read();

    // Initialize telemetry.
    if config.prometheus.unwrap_or_default() {
        log::info!("Metrics are enabled using Prometheus.");
        helpers::telemetry::register_custom_metrics();
    }

    if let Some(url) = config.jaeger_url {
        log::info!("Tracing requests activated with Jaeger.");
        helpers::telemetry::init_tracer(&url)?;
        opentelemetry::global::tracer("tracing-jaeger")
    }

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
        },
        Err(error) => {
            // A connection failure renders the entire API unstable and unusable.
            log::error!(
                "Cannot initialize Apache Cassandra or ScyllaDB connection: {}",
                error
            );
            std::process::exit(0);
        },
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
        },
        Err(error) => {
            // In the event that establishing a connections pool encounters any difficulties, it will be duly logged.
            // Such a scenario might lead to suboptimal performance in specific requests.
            // It makes also impossible to create temporary code, for instance, for OAuth requests.
            log::warn!(
                "Cannot initialize Memcached pool, this could result in poor performance: {}",
                error
            );

            db::memcache::MemcachePool { connection: None }
        },
    };

    // Init message broker.
    let broker: Arc<db::broker::Broker> = match (
        config.database.kafka.as_ref(),
        config.database.rabbitmq.as_ref(),
    ) {
        (Some(_), Some(_)) => {
            log::error!("You have declared Kafka and RabbitMQ. Only a broker message can be used. No broker messages will be started, and other services will receive no data.");
            Arc::new(db::broker::empty())
        },
        (Some(kafka_conn), None) => {
            match db::broker::with_kafka(
                kafka_conn.hosts.clone(),
                kafka_conn.pool_size,
            ) {
                Ok(broker) => {
                    log::info!("Kafka pool connection created successfully.");
                    Arc::new(broker)
                },
                Err(error) => {
                    log::error!("Could not initialize Kafka pool: {}", error);
                    Arc::new(db::broker::empty())
                },
            }
        },
        (None, Some(rabbit_conn)) => {
            match db::broker::with_rabbitmq(
                rabbit_conn.hosts.clone(),
                rabbit_conn.pool_size,
            ) {
                Ok(broker) => {
                    log::info!(
                        "RabbitMQ pool connection created successfully."
                    );
                    Arc::new(broker)
                },
                Err(error) => {
                    log::error!(
                        "Could not initialize RabbitMQ pool: {}",
                        error
                    );
                    Arc::new(db::broker::empty())
                },
            }
        },
        _ => {
            log::warn!(
                "No message broker set; other services will not be notified of user changes."
            );
            Arc::new(db::broker::empty())
        },
    };

    // Create needed tables.
    if let Err(error) = scylladb.create_tables().await {
        log::error!("Failed to create tables: {}", error);
    } else {
        log::trace!("Successfully created tables, if they didn't exist.");
    }

    let create_route = warp::path("create")
        .and(warp::post())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::body::json())
        .and(warp::header::optional::<String>("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(router::create_user);

    let login_route = warp::path("login")
        .and(warp::post())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::body::json())
        .and(warp::header::optional::<String>("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(router::login_user);

    let get_user_route = warp::path!("users" / String)
        .and(warp::get())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::header::optional::<String>("authorization"))
        .and_then(router::get_user);

    let update_user_route = warp::path("users")
        .and(warp::path("@me"))
        .and(warp::patch())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(router::with_broker(Arc::clone(&broker)))
        .and(warp::header::<String>("authorization"))
        .and(warp::body::json())
        .and_then(router::update_user);

    warp::serve(
        warp::any()
            .and(warp::options())
            .map(|| "OK")
            .or(warp::head()
                .map(|| "OK")
                .or(create_route)
                .or(login_route)
                .or(get_user_route)
                .or(update_user_route)
                .or(warp::path("metrics")
                    .and_then(helpers::telemetry::metrics_handler))),
    )
    .run(([0, 0, 0, 0], config.port))
    .await;

    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}
