mod database;
#[forbid(unsafe_code)]
#[deny(missing_docs, unused_mut)]
mod metrics;
mod router;
mod status;

use axum::{
    http::{header, Method, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::future::ready;
use std::process;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing.
    let (layer, task) = tracing_loki::builder()
        .label("host", "autha")?
        .extra_field("pid", process::id().to_string())?
        .build_url(url::Url::parse("http://loki:3100")?)?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
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

    // build our application with a route.
    let app = Router::new()
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user))
        // `GET /status.json` goes to `status`.
        .route("/status.json", get(router::status::status))
        // `GET /metrics`
        .route("/metrics", get(move || ready(recorder_handle.render())))
        .route_layer(middleware::from_fn(metrics::track_metrics))
        .route_layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS, Method::PATCH])
                .vary([header::AUTHORIZATION]),
        );

    let listener = tokio::net::TcpListener::bind(format!(
        "0.0.0.0:{}",
        std::env::var("PORT").unwrap_or(8080.to_string())
    ))
    .await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn create_user(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<CreateUser>,
) -> (StatusCode, Json<User>) {
    // insert your application logic here
    let user = User {
        id: 1337,
        username: payload.username,
    };

    // this will be converted into a JSON response
    // with a status code of `201 Created`
    (StatusCode::CREATED, Json(user))
}

// the input to our `create_user` handler
#[derive(Deserialize)]
struct CreateUser {
    username: String,
}

// the output to our `create_user` handler
#[derive(Serialize)]
struct User {
    id: u64,
    username: String,
}
