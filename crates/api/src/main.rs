//! Autha account manager binary entry point.

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

mod config;
mod middleware;
mod state;
mod telemetry;

use std::env;
use std::future::ready;
use std::sync::Arc;
use std::time::Duration;

use adapters::inbound::{http, ldap};
use adapters::outbound::mail::RabbitMqMailer;
use adapters::outbound::persistence::postgres;
use adapters::outbound::{crypto, token};
use application::ports::outbound::{LdapPort, Mailer};
use axum::routing::{get, patch, post};
use axum::{Router, middleware as axum_middleware};
use config::ServerConfig;
use opentelemetry::trace::TracerProvider;
use tower_http::timeout::RequestBodyTimeoutLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

use crate::middleware::auth_middleware;

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

    postgres::pool::migrate(&db_pool).await?;

    let account_repo =
        Arc::new(postgres::account_repository::PgAccountRepository::new(
            db_pool.clone(),
        ));
    let refresh_token_repo =
        Arc::new(postgres::token_repository::PgRefreshTokenRepository::new(
            db_pool.clone(),
        ));

    let clock = Arc::new(adapters::outbound::clock::SystemClock);

    let master_key = zeroize::Zeroizing::new(
        env::var("MASTER_KEY")
            .expect("MASTER_KEY env var is required")
            .into_bytes(),
    );
    let salt = env::var("SALT")
        .expect("SALT env var is required")
        .into_bytes();

    let crypto = Arc::new(crypto::CryptoAdapter::new(
        clock.clone(),
        master_key,
        salt,
        config.argon2.memory_cost,
        config.argon2.iterations,
        config.argon2.parallelism,
    )?);
    let mailer = if let Some(cfg) = &config.mail {
        Some(Arc::new(
            RabbitMqMailer::new(
                &cfg.address,
                &cfg.username,
                &cfg.password,
                &cfg.queue,
            )
            .await?,
        ) as Arc<dyn Mailer>)
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
        Arc::new(token::TokenAdapter::new(token_signer, refresh_manager));
    let ldap_client = if let Some(cfg) = &config.ldap {
        let ldap_config =
            ldap::config::LdapConfig::new(&cfg.address, &cfg.base_dn);
        Some(Arc::new(ldap::client::LdapClient::new(ldap_config)?)
            as Arc<dyn LdapPort>)
    } else {
        None
    };
    let telemetry_adapter =
        Arc::new(adapters::outbound::telemetry::TracingTelemetry);

    let status_uc =
        application::usecases::StatusUseCase::new(config.clone().into());
    let create_account_uc = application::usecases::CreateAccountUseCase::new(
        account_repo.clone(),
        refresh_token_repo.clone(),
        crypto.clone(),
        mailer.clone(),
        token.clone(),
        telemetry_adapter.clone(),
        clock.clone(),
    );
    let authenticate_uc = application::usecases::AuthenticateUseCase::new(
        account_repo.clone(),
        refresh_token_repo,
        ldap_client,
        crypto.clone(),
        token.clone(),
        telemetry_adapter,
        clock,
    );
    let get_user_uc = application::usecases::GetUserUseCase::new(
        account_repo.clone(),
        token.clone(),
        config.into(),
    );
    let update_user_uc = application::usecases::UpdateUserUseCase::new(
        account_repo,
        crypto,
        mailer,
    );
    let state = state::AppState {
        status: Arc::new(status_uc),
        create_account: Arc::new(create_account_uc),
        authenticate: Arc::new(authenticate_uc),
        get_user: Arc::new(get_user_uc),
        update_user: Arc::new(update_user_uc),
        token,
    };

    let app = Router::new()
        .route("/metrics", get(move || ready(recorder_handle.render())))
        .route("/status.json", get(http::status::status_handler))
        .route("/create", post(http::create::create_account_handler))
        .route("/login", post(http::login::login_handler))
        .route("/users/:id", get(http::get_user::get_user_handler))
        .route(
            "/users/@me",
            patch(http::update_user::handler).route_layer(
                axum_middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                ),
            ),
        )
        .with_state(state)
        .route_layer(axum_middleware::from_fn(telemetry::track))
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
    let _ = fs::remove_file(path);

    let listener = tokio::net::UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o766))?;
    tracing::info!(?path, "listening on unix socket");

    let builder = hyper_util::server::conn::auto::Builder::new(
        hyper_util::rt::TokioExecutor::new(),
    );

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::error!(%err, "error accepting connection");
                continue;
            },
        };

        let tower_service = app.clone();
        let builder = builder.clone();

        tokio::spawn(async move {
            let socket = hyper_util::rt::TokioIo::new(stream);
            let service =
                hyper_util::service::TowerToHyperService::new(tower_service);

            if let Err(err) = builder.serve_connection(socket, service).await {
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
