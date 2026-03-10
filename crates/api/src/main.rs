//! Autha account manager binary entry point.

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

mod config;
mod telemetry;

use std::env;
use std::future::ready;
use std::sync::Arc;
use std::time::Duration;

use adapters::inbound::{http, ldap};
use adapters::outbound::mail::RabbitMqMailer;
use adapters::outbound::persistence::postgres;
use adapters::outbound::{crypto, token};
use application::ports::outbound::Mailer;
use axum::Router;
use axum::routing::{get, post};
use config::ServerConfig;
use opentelemetry::trace::TracerProvider;
use tower_http::timeout::RequestBodyTimeoutLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        format!(
            "autha={level},tower_http={level},axum::rejection=trace,{level}"
        )
        .into()
    });

    let tracer_provider = telemetry::setup_tracer()?;
    let tracer = tracer_provider.tracer("autha");
    let otel_url = env::var("OTEL_URL")
        .unwrap_or_else(|_| "http://localhost:4317".into());

    let logging_layer = telemetry::setup_logging(&otel_url)?.with_filter(
        EnvFilter::new("info")
            .add_directive("hyper=off".parse()?)
            .add_directive("tonic=off".parse()?),
    );

    tracing_subscriber::registry()
        .with(env_filter)
        .with(logging_layer)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let recorder_handle = telemetry::setup_metrics_recorder()?;

    let config = ServerConfig::load_default()?;
    tracing::info!(name = %config.name, url = %config.url, "configuration loaded");

    tracing::info!(url = %config.postgres.address, "connecting to postgres");
    let db_pool = postgres::pool::create_pool(
        &config.postgres_url(),
        config.postgres.pool_size,
    )
    .await?;

    postgres::pool::migrate(db_pool.clone()).await?;

    let account_repo =
        Box::new(postgres::account_repository::PgAccountRepository::new(
            db_pool.clone(),
        ));
    let refresh_token_repo =
        Box::new(postgres::token_repository::PgRefreshTokenRepository::new(
            db_pool.clone(),
        ));

    let master_key = zeroize::Zeroizing::new(
        env::var("MASTER_KEY")
            .expect("MASTER_KEY env var is required")
            .into_bytes(),
    );
    let salt = env::var("SALT")
        .expect("SALT env var is required")
        .into_bytes();

    let crypto = Box::new(crypto::CryptoAdapter::new(
        master_key,
        salt,
        config.argon2.memory_cost,
        config.argon2.iterations,
        config.argon2.parallelism,
    )?);
    let mailer = if let Some(cfg) = &config.mail {
        Some(Box::new(
            RabbitMqMailer::new(
                &cfg.address,
                &cfg.username,
                &cfg.password,
                &cfg.queue,
            )
            .await?,
        ) as Box<dyn Mailer>)
    } else {
        None
    };
    let token_signer = token::jwt::TokenSigner::new(
        &config.token.key_id,
        &config.name,
        &config.token.public_key_pem,
        &config.token.private_key_pem,
    )?;
    let refresh_manager = token::SecureRefreshTokenManager::new();
    let token =
        Box::new(token::TokenAdapter::new(token_signer, refresh_manager));
    let ldap_client = if let Some(cfg) = &config.ldap {
        let ldap_config =
            ldap::config::LdapConfig::new(&cfg.address, &cfg.base_dn);
        Some(ldap::client::LdapClient::new(ldap_config)?)
    } else {
        None
    };
    let telemetry_adapter =
        Box::new(adapters::outbound::telemetry::TracingTelemetry);
    let clock = Box::new(adapters::outbound::clock::SystemClock);

    let create_account_uc = application::usecases::CreateAccountUseCase::new(
        account_repo,
        refresh_token_repo,
        crypto,
        mailer,
        token,
        telemetry_adapter,
        clock,
    );
    let shared_service = Arc::new(create_account_uc);

    let app = Router::new()
        .route("/metrics", get(move || ready(recorder_handle.render())))
        .route(
            "/create",
            post(
                http::create::create_account_handler::<
                    Arc<application::usecases::CreateAccountUseCase>,
                >,
            ),
        )
        .with_state(shared_service)
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(5)));

    match env::var("UNIX_SOCKET") {
        Ok(path) => listen_unix_socket(&path, app).await,
        Err(_) => listen_tcp(app).await,
    }
}

/// Start a TCP listener.
async fn listen_tcp(app: Router) -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    Ok(axum::serve(listener, app).await?)
}

/// Start a Unix socket listener.
#[cfg(unix)]
async fn listen_unix_socket(
    path: &str,
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;

    // Remove existing socket file if it exists.
    if std::path::Path::new(&path).exists() {
        fs::remove_file(path)?;
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o766))?;
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
async fn listen_unix_socket(
    _path: &str,
    _app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Unix sockets are not supported on this platform".into())
}
