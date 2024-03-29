mod helpers;
mod model;
mod router;

#[macro_use]
extern crate lazy_static;
use std::{sync::Arc, time::Duration};
use warp::{
    http::{Method, Response},
    Filter,
};

/// Create CORS headers.
pub fn cors() -> warp::cors::Cors {
    warp::cors()
        .allow_any_origin()
        .allow_methods(&[
            Method::OPTIONS,
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_header("*")
        .build()
}

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
        .expect("Cannot apply fern to log");

    // Read configuration file.
    let config = helpers::config::read();

    // Initialize telemetry.
    #[cfg(feature = "telemetry")]
    if config.prometheus.unwrap_or_default() {
        log::info!("Metrics are enabled using Prometheus.");
        helpers::telemetry::register_custom_metrics();
    }

    #[cfg(feature = "telemetry")]
    if let Some(url) = config.jaeger_url {
        log::info!("Tracing requests activated with Jaeger.");
        helpers::telemetry::init_tracer(&url).unwrap();
        opentelemetry::global::tracer("tracing-jaeger");
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
        #[cfg(feature = "kafka")]
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
        #[cfg(feature = "rabbitmq")]
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
    if let Err(error) = helpers::queries::create_tables(&scylladb).await {
        log::error!("Failed to create tables: {}", error);
    } else {
        log::trace!("Successfully created tables, if they didn't exist.");
    }

    // Init prepared queries.
    helpers::queries::init(&scylladb).await.unwrap();

    // Rate-limiters per method.
    let get_limiter =
        Arc::new(autha_limits::RateLimiter::new(100, Duration::from_secs(60)));
    let patch_limiter =
        Arc::new(autha_limits::RateLimiter::new(5, Duration::from_secs(30)));

    let create_route = warp::path("create")
        .and(warp::post())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(router::with_broker(Arc::clone(&broker)))
        .and(warp::body::content_length_limit(8_000))
        .and(warp::body::json())
        .and(warp::header::optional::<String>("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(router::create::handle);

    let login_route = warp::path("login")
        .and(warp::post())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::body::content_length_limit(5_000))
        .and(warp::body::json())
        .and(warp::header::optional::<String>("cf-turnstile-token"))
        .and(warp::header::optional::<String>("X-Forwarded-For"))
        .and(warp::addr::remote())
        .and_then(router::login::handle);

    let get_user_route = warp::path!("users" / String)
        .and(warp::get())
        .and(router::with_metric())
        .and(autha_limits::warp::rate_limiter(Arc::clone(&get_limiter)))
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::header::optional::<String>("authorization"))
        .and_then(router::users::get);

    let update_user_route = warp::path("users")
        .and(warp::path("@me"))
        .and(warp::patch())
        .and(router::with_metric())
        .and(autha_limits::warp::rate_limiter(Arc::clone(&patch_limiter)))
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(router::with_broker(Arc::clone(&broker)))
        .and(warp::header::<String>("authorization"))
        .and(warp::body::content_length_limit(1024 * 500)) // 500kb.
        .and(warp::body::json())
        .and_then(router::users::update);

    // OAuth.
    let create_oauth = warp::path("oauth2")
        .and(warp::path("authorize"))
        .and(warp::get())
        .and(router::with_metric())
        .and(autha_limits::warp::rate_limiter(Arc::clone(&get_limiter)))
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::header::<String>("authorization"))
        .and(warp::query::<model::query::OAuth>())
        .and_then(router::create_token);

    let access_token = warp::path("oauth2")
        .and(warp::path("token"))
        .and(warp::post())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(router::with_memcached(memcached_pool.clone()))
        .and(warp::body::content_length_limit(5_000))
        .and(warp::body::form())
        .and_then(router::oauth::grant);

    let revoke_token = warp::path("oauth2")
        .and(warp::path("token"))
        .and(warp::path("revoke"))
        .and(warp::post())
        .and(router::with_metric())
        .and(router::with_scylla(Arc::clone(&scylladb)))
        .and(warp::body::content_length_limit(5_000))
        // This should NOT be json but form do not work.
        .and(warp::body::json())
        .and_then(router::oauth::revoke::revoke);

    #[cfg(feature = "telemetry")]
    let metrics =
        warp::path("metrics").and_then(helpers::telemetry::metrics_handler);
    #[cfg(not(feature = "telemetry"))]
    let metrics = warp::path("metrics").map(|| "no metrics");

    warp::serve(
        warp::any()
            .and(warp::options())
            .map(|| {
                Response::builder()
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Headers", "*")
                    .header(
                        "Access-Control-Allow-Methods",
                        "GET, POST, PATCH, DELETE",
                    )
                    .body("OK")
            })
            .or(create_route
                .or(login_route)
                .or(get_user_route)
                .or(update_user_route)
                .or(create_oauth)
                .or(access_token)
                .or(revoke_token)
                .or(metrics))
            .recover(router::handle_rejection)
            .with(cors()),
    )
    .run(([0, 0, 0, 0], config.port))
    .await;
}
