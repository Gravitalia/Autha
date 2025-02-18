#[forbid(unsafe_code)]
#[deny(missing_docs, unused_mut)]
mod crypto;
mod database;
mod metrics;
mod router;
mod status;
mod user;
mod well_known;

use axum::{
    http::{header, Method},
    middleware,
    routing::{get, post},
    Router,
};
use opentelemetry::global;
use opentelemetry::trace::{Span, Tracer};
use opentelemetry::KeyValue;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tower::{Layer, Service};
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::RequestBodyTimeoutLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use well_known::well_known;

use std::env;
use std::future::ready;
use std::future::Future;
use std::pin::Pin;
use std::process;
use std::task::{Context, Poll};
use std::time::Duration;

#[derive(Clone)]
pub struct AppState {
    pub config: status::Configuration,
    pub db: database::Database,
}

#[derive(Clone)]
struct OTelLayer;

impl<S> Layer<S> for OTelLayer {
    type Service = OTelService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OTelService { inner }
    }
}

#[derive(Clone)]
struct OTelService<S> {
    inner: S,
}

impl<Req, S> Service<Req> for OTelService<S>
where
    S: Service<Req> + Clone + Send + 'static,
    S::Future: Send + 'static,
    Req: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> Self::Future {
        let tracer = global::tracer("tracing-http");

        let mut otel_span = tracer.start("http-request");
        otel_span.set_attribute(KeyValue::new("type", "http"));

        let fut = self.inner.call(req);
        Box::pin(async move {
            let res = fut.await;
            otel_span.end();
            res
        })
    }
}

fn tracer() -> SdkTracerProvider {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .unwrap();

    SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(Resource::builder().with_service_name("autha").build())
        .build()
}

use axum::body::Bytes;
use tower::ServiceBuilder;
use tower_http::LatencyUnit;

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
        // Add OLTP tracing.
        .layer(OTelLayer)
        // Set a timeout.
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        // Add CORS preflight support.
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS, Method::PATCH])
                .vary([header::AUTHORIZATION]),
        );

    Router::new()
        // `GET /status.json` goes to `status`.
        .route("/status.json", get(router::status::status))
        // `POST /login` goes to `login`.
        .route("/login", post(router::login::login))
        // `POST /create` goes to `create`.
        .route("/create", post(router::create::create))
        // `GET /users/:ID` goes to `get`.
        .route("/users/{user_id}", get(router::user::get))
        .with_state(state.clone())
        .nest("/.well-known", well_known(state))
        .route_layer(middleware::from_fn(metrics::track_metrics))
        .layer(middleware)
}

#[tokio::main]
#[tracing::instrument]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tracer_provider = tracer();
    global::set_tracer_provider(tracer_provider.clone());

    // initialize tracing.
    let (layer, task) = tracing_loki::builder()
        .label("host", "autha")?
        .extra_field("pid", process::id().to_string())?
        .build_url(url::Url::parse("http://loki:3100")?)?;

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

    tokio::spawn(task); // init Loki delivrerer.

    // init all telemetry logic.
    let recorder_handle = metrics::setup_metrics_recorder()?;

    // load configuration and let it on memory.
    // init databases connection.
    let state = AppState {
        config: status::Configuration::read(None)?,
        db: database::Database::new(
            &env::var("POSTGRES_URL").unwrap_or_else(|_| database::DEFAULT_PG_URL.into()),
        )
        .await?,
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
    axum::serve(listener, app).await?;

    tracer_provider.shutdown().unwrap();

    Ok(())
}
