//!  Autha is a lightweight account manager for decentralized world.

#[forbid(unsafe_code)]
#[deny(missing_docs, unused_mut)]
mod crypto;
mod database;
pub mod error;
mod ldap;
mod mail;
mod middleware;
mod router;
pub mod telemetry;
mod token;
mod totp;
mod user;
mod well_known;

pub mod config;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{Method, StatusCode, header};
use axum::routing::{get, post};
use axum::{Router, middleware as AxumMiddleware};
use error::ServerError;
use tower::ServiceBuilder;
use tower_http::LatencyUnit;
use tower_http::cors::{Any, CorsLayer};
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{
    DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer,
};

/// MUST NEVER be used in production.
#[cfg(test)]
pub async fn make_request(
    state: Option<&AppState>,
    app: Router,
    method: Method,
    path: &str,
    body: String,
) -> axum::http::Response<axum::body::Body> {
    use axum::extract::Request;
    use tower::util::ServiceExt;

    let token = match state {
        Some(state) => state.token.create("admin").expect("cannot create JWT"),
        None => String::default(),
    };

    dbg!(&token, &method, path, &body);

    app.oneshot(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, token)
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
    pub ldap: Option<ldap::Ldap>,
    pub crypto: Arc<crypto::Crypto>,
    pub token: token::TokenManager,
    pub mail: mail::MailManager,
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
                .make_span_with(DefaultMakeSpan::new().include_headers(true). level(tracing::Level::INFO))
                .on_request(DefaultOnRequest::new())
                .on_response(DefaultOnResponse::new(). include_headers(true). latency_unit(LatencyUnit::Micros)),
        )
        // Set a timeout. 
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(10)))
        // Remove senstive headers from trace.
        .layer(SetSensitiveHeadersLayer::new([header::AUTHORIZATION, header::COOKIE]))
        // Add CORS preflight support.
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE, Method::OPTIONS])
                .allow_headers(Any)
                .vary([header::AUTHORIZATION]),
        );

    let create_router = Router::new()
        // Initialize telemetry.
        // initialize tracing.
        // `POST /create` goes to `create`.
        .route("/", post(router::create::handler))
        .route_layer(AxumMiddleware::from_fn_with_state(
            state.clone(),
            middleware::consume_invites,
        ));

    Router::new()
        // `GET /status. json` goes to `status`.
        .route("/status.json", get(router::status::status))
        // `POST /login` goes to `login`.
        .route("/login", post(router::login::handler))
        // POST `/oauth/token`
        .route("/oauth/token", post(router::users::refresh_token::handler))
        .nest("/create", create_router)
        .nest("/users", router::users::router(state.clone()))
        .with_state(state.clone())
        .nest("/.well-known", well_known::well_known(state))
        .route_layer(AxumMiddleware::from_fn(telemetry::track))
        .layer(middleware)
}

/// Initialize the application state.
pub async fn initialize_state() -> Result<AppState, Box<dyn std::error::Error>>
{
    // read configuration file.  let it in memory.
    let config = config::Configuration::default().read()?;

    // initialize LDAP.
    let ldap = if let Some(cfg) = &config.ldap {
        let ldap_config = ldap::LdapConfig::new(
            &cfg.address,
            &cfg.base_dn,
            &cfg.additional_users_dn,
        )?;

        Some(
            ldap::Ldap::connect(
                ldap_config,
                cfg.user.as_deref(),
                cfg.password.as_deref(),
            )
            .await?,
        )
    } else {
        None
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
                config.pool_size.unwrap_or(database::DEFAULT_POOL_SIZE),
            )
            .await?
        },
        None => {
            // A database is required even with LDAP.
            // PostgreSQL manage user publics keys.
            tracing::error!("missing `postgres` entry on `config. yaml` file");
            std::process::exit(0);
        },
    };

    // execute migrations scripts on start.
    sqlx::migrate!().run(&db.postgres).await?;

    let key =
        std::env::var("KEY").expect("missing `KEY` environnement variable");
    let salt =
        std::env::var("SALT").expect("missing `SALT` environnement variable");
    let crypto =
        Arc::new(crypto::Crypto::new(config.argon2.clone(), key, salt)?);

    // handle jwt.
    let Some(token) = &config.token else {
        tracing::warn!("missing `token` entry on `config.yaml` file");
        std::process::exit(0);
    };
    let mut token = token::TokenManager::new(
        &config.url,
        token.key_id.clone(),
        &token.public_key_pem,
        &token.private_key_pem,
    )?;

    if let Some(audience) =
        config.token.as_ref().and_then(|t| t.audience.as_ref())
    {
        token.audience(audience);
    }

    // handle mail sender.
    let mail = if let Some(cfg) = &config.mail {
        mail::MailManager::new(cfg).await?
    } else {
        mail::MailManager::default()
    };

    Ok(AppState {
        config,
        db,
        ldap,
        crypto,
        token,
        mail,
    })
}
