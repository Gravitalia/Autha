#[forbid(unsafe_code)]
#[deny(missing_docs, unused_mut)]
mod crypto;
mod database;
mod router;
mod status;
mod telemetry;
mod user;
mod well_known;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::middleware::Next;
use axum::response::Response as AxumResponse;
use axum::routing::patch;
use axum::{
    http::{header, Method},
    middleware,
    routing::{get, post},
    Router,
};
use opentelemetry::global;
use router::ServerError;
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

#[derive(Clone)]
pub struct AppState {
    pub config: status::Configuration,
    pub db: database::Database,
}

/// Create router.
pub fn app(state: AppState) -> Router {
    // Custom middleware for authentification.
    async fn auth(
        State(db): State<database::Database>,
        user_id: Option<Path<String>>,
        mut req: Request,
        next: Next,
    ) -> Result<AxumResponse, ServerError> {
        let user_id = match user_id {
            Some(user_id) => user_id.to_string(),
            None => "@me".to_owned(),
        };
        let user_id = if user_id == "@me" {
            match req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|header| header.to_str().ok())
            {
                Some(token) => {
                    match sqlx::query!("SELECT user_id FROM tokens WHERE token = $1", token)
                        .fetch_one(&db.postgres)
                        .await
                    {
                        Ok(token_data) => token_data.user_id,
                        Err(_) => return Err(ServerError::Unauthorized),
                    }
                }
                None => return Err(ServerError::Unauthorized),
            }
        } else {
            user_id
        };
        
        let user = user::User::default()
            .with_id(user_id)
            .get(&db.postgres)
            .await?;

        req.extensions_mut().insert::<user::User>(user);
        Ok(next.run(req).await)
    }

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
                .vary([header::AUTHORIZATION]),
        );

    Router::new()
        // `GET /users/:ID` goes to `get`.
        .route("/users/{user_id}", get(router::user::get))
        .route("/users/@me", get(router::user::get))
        // `PATCH /users/@me` goes to `patch`. Authorization required.
        .route("/users/@me", patch(router::user::patch))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
        // `GET /status.json` goes to `status`.
        .route("/status.json", get(router::status::status))
        // `POST /login` goes to `login`.
        .route("/login", post(router::login::login))
        // `POST /create` goes to `create`.
        .route("/create", post(router::create::create))
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
    let layer = telemetry::setup_logging()?.with_filter(filter);
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
