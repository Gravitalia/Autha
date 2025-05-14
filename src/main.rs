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
use axum::http::{header, Method};
use axum::routing::{get, post};
use axum::{middleware, Router};
use error::ServerError;
use opentelemetry::global;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::RequestBodyTimeoutLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse};
use tower_http::LatencyUnit;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_subscriber::{prelude::*, EnvFilter};

use std::env;
use std::future::ready;
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
    pub config: config::Configuration,
    pub db: database::Database,
    pub ldap: ldap::Ldap,
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
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros)),
        )
        // Set a timeout.
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        // Add CORS preflight support.
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS, Method::PATCH])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .vary([header::AUTHORIZATION]),
        );

    let create_router = Router::new()
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
    // Initialize telemetry.
    // initialize tracing.
    let tracer_provider = telemetry::setup_tracer()?;
    global::set_tracer_provider(tracer_provider.clone());

    // initialize logging.
    let filter = EnvFilter::new("info")
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("opentelemetry=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());
    let layer =
        telemetry::setup_logging(&env::var("OTEL_URL").unwrap_or("http://localhost:4317".into()))?
            .with_filter(filter);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    // initialize metrics.
    let recorder_handle = telemetry::setup_metrics_recorder()?;

    // read configuration file. let it in memory.
    let config = config::Configuration::default().read()?;

    // initialize LDAP.
    let ldap = if let Some(ref config) = config.ldap {
        ldap::Ldap::new(
            &config.address,
            config.user.clone(),
            config.password.clone(),
        )
        .await
        .or_else(|err| {
            tracing::error!(error = err.to_string(), "LDAP connection failed");
            Ok::<_, ldap3::LdapError>(ldap::Ldap::default())
        })?
    } else {
        ldap::Ldap::default()
    };

    let db = if let Some(ref config) = config.postgres {
        database::Database::new(&config.address).await?
    } else {
        // A database is required even with LDAP.
        // PostgreSQL manage user publics keys.
        tracing::error!("missing `postgres` entry on `config.yaml` file");
        panic!()
    };

    let state = AppState { config, db, ldap };

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
    axum::serve(listener, app).await?;

    tracer_provider.shutdown().unwrap();

    Ok(())
}
