//! Autha is a lightweight account manager for decentralized world.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

mod config;
#[forbid(unsafe_code)]
#[deny(missing_docs, unused_mut)]
mod crypto;
mod database;
mod error;
mod ldap;
mod router;
mod telemetry;
mod totp;
mod user;
mod well_known;

use axum::body::Bytes;
use axum::http::{Method, header};
use axum::routing::{get, post};
use axum::{Router, middleware};
use error::ServerError;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use tower::ServiceBuilder;
use tower_http::LatencyUnit;
use tower_http::cors::{Any, CorsLayer};
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;
use tower_http::timeout::RequestBodyTimeoutLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse};
use tower_http::trace::{DefaultOnRequest, TraceLayer};
use tracing_subscriber::{EnvFilter, prelude::*};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::env;
use std::future::ready;
use std::sync::Arc;
use std::time::Duration;

/// MUST NEVER be used in production.
#[cfg(test)]
pub async fn make_request(
    app: Router,
    method: Method,
    path: &str,
    body: String,
) -> axum::http::Response<axum::body::Body> {
    use axum::extract::Request;
    use tower::util::ServiceExt;

    app.oneshot(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap()
}

/// State sharing between routes.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Configuration>,
    pub db: database::Database,
    pub ldap: ldap::Ldap,
    pub crypto: crypto::Cipher,
}

/// Create router.
pub fn app(state: AppState) -> Router {
    let middleware = ServiceBuilder::new()
        // Add high level tracing/logging to all requests.
        .layer(
            TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _span: &tracing::Span| {
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                })
                .make_span_with(DefaultMakeSpan::new().include_headers(true).level(tracing::Level::INFO))
                .on_request(DefaultOnRequest::new())
                .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros)),
        )
        // Set a timeout.
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        // Remove senstive headers from trace.
        .layer(SetSensitiveHeadersLayer::new([header::AUTHORIZATION, header::COOKIE]))
        // Add CORS preflight support.
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .vary([header::AUTHORIZATION]),
        );

    let create_router = Router::new()
        // Initialize telemetry.
        // initialize tracing.
        // `POST /create` goes to `create`.
        .route("/", post(router::create::create))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            router::create::middleware,
        ));

    Router::new()
        // `GET /status.json` goes to `status`.
        .route("/status.json", get(router::status::status))
        // `POST /login` goes to `login`.
        .route("/login", post(router::login::login))
        .nest("/create", create_router)
        .nest("/users", router::users::router(state.clone()))
        .with_state(state.clone())
        .nest("/.well-known", well_known::well_known(state))
        .route_layer(middleware::from_fn(telemetry::track))
        .layer(middleware)
}

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
    let tracer_provider = telemetry::setup_tracer()?;
    let tracer = tracer_provider.tracer("autha");
    global::set_tracer_provider(tracer_provider.clone());

    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let logging_layer =
        telemetry::setup_logging(&env::var("OTEL_URL").unwrap_or("http://localhost:4317".into()))?
            .with_filter(filter);

    let level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
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
    let recorder_handle = telemetry::setup_metrics_recorder()?;

    // read configuration file. let it in memory.
    let config = config::Configuration::default().read()?;

    // initialize LDAP.
    let ldap = match config.ldap {
        Some(ref config) => ldap::Ldap::new(
            &config.address,
            config.user.clone(),
            config.password.clone(),
        )
        .await
        .or_else(|err| {
            tracing::error!(error = err.to_string(), "LDAP connection failed");
            Ok::<_, ldap3::LdapError>(ldap::Ldap::default())
        })?,
        None => ldap::Ldap::default(),
    };

    let db = match config.postgres {
        Some(ref config) => {
            database::Database::new(
                &config.address,
                &config
                    .username
                    .clone()
                    .unwrap_or(database::DEFAULT_CREDENTIALS.into()),
                &config
                    .password
                    .clone()
                    .unwrap_or(database::DEFAULT_CREDENTIALS.into()),
                &config
                    .database
                    .clone()
                    .unwrap_or(database::DEFAULT_DATABASE_NAME.into()),
            )
            .await?
        }
        None => {
            // A database is required even with LDAP.
            // PostgreSQL manage user publics keys.
            tracing::error!("missing `postgres` entry on `config.yaml` file");
            panic!()
        }
    };

    let crypto = if let Ok(key) = std::env::var("KEY") {
        crypto::Cipher::key(key)?
    } else {
        tracing::warn!("missing `KEY` environnement; set it in production!");

        let key = [0x42; 32];
        crypto::Cipher::key(hex::encode(key))?
    };

    let state = AppState {
        config,
        db,
        ldap,
        crypto,
    };

    // build our application with a route.
    let app = app(state)
        // `GET /metrics`
        .route("/metrics", get(move || ready(recorder_handle.render())))
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(5)));

    let listener = tokio::net::TcpListener::bind(format!(
        "0.0.0.0:{}",
        env::var("PORT").unwrap_or(8080.to_string())
    ))
    .await?;
    tracing::info!("listening on {}", listener.local_addr()?);

    tokio::select! {
        _ = axum::serve(listener, app) => {
            tracing::info!("server is stopping");
            tracer_provider.shutdown().unwrap();
        },
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl+c pressed... should only happen on dev mode");
        },
    };

    Ok(())
}
