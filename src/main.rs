//! Autha account manager binary entry point.

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use autha::{app, initialize_state};
#[cfg(unix)]
use axum::Router;
use axum::routing::get;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use tower_http::timeout::RequestBodyTimeoutLayer;
use tracing_subscriber::{EnvFilter, prelude::*};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::env;
use std::future::ready;
use std::time::Duration;

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // dynamic heap analysis.
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Telemetry.
    let filter = EnvFilter::new("info")
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());

    // initialize logging.
    let tracer_provider = autha::telemetry::setup_tracer()?;
    let tracer = tracer_provider.tracer("autha");
    global::set_tracer_provider(tracer_provider.clone());

    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let logging_layer = autha::telemetry::setup_logging(
        &env::var("OTEL_URL").unwrap_or("http://localhost:4317".into()),
    )?
    .with_filter(filter);

    let level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    format!(
                        "{}={level},tower_http={level},axum::rejection=trace",
                        env!("CARGO_CRATE_NAME")
                    )
                    .into()
                }),
        )
        .with(logging_layer)
        .with(telemetry_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    // initialize metrics.
    let recorder_handle = autha::telemetry::setup_metrics_recorder()?;

    // Initialize application state.
    let state = initialize_state().await?;

    // build our application with a route.
    let app = app(state)
        // `GET /metrics`
        .route("/metrics", get(move || ready(recorder_handle.render())))
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(5)));

    // either start a UNIX socket or a TCP listener.
    if let Ok(path) = env::var("UNIX_SOCKET") {
        listen_unix_socket(&path, app).await
    } else {
        listen_tcp(app).await
    }
}

async fn listen_tcp(app: Router) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!(
        "0.0.0. 0:{}",
        env::var("PORT").unwrap_or(8080.to_string())
    ))
    .await?;
    tracing::info!("listening on {}", listener.local_addr()?);

    Ok(axum::serve(listener, app).await?)
}

#[cfg(unix)]
async fn listen_unix_socket(
    path: &str,
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    // Remove existing socket file if it exists
    if std::path::Path::new(&path).exists() {
        std::fs::remove_file(path)?;
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    tracing::info!(?path, "listening on unix socket");

    loop {
        let (stream, _) = listener.accept().await?;
        let tower_service = app.clone();
        tokio::spawn(async move {
            let socket = hyper_util::rt::TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    use tower::Service;
                    let mut service = tower_service.clone();
                    async move { service.call(request).await }
                },
            );
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(socket, hyper_service)
            .await
            {
                tracing::error!(%err, "error serving connection");
            }
        });
    }
}

#[cfg(not(unix))]
fn listen_unix_socket(
    path: &str,
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::error!("UNIX sockets are not supported on this platform");
    exit(1);
}
