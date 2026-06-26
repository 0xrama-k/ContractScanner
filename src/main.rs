mod analyzers;
mod api;
mod app;
mod error;
mod infra;
mod models;
mod repositories;
mod services;
mod util;

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::infra::config::Config;

#[tokio::main]
async fn main() {
    // Load .env if present (ignored in production where env is set directly).
    let _ = dotenvy::dotenv();

    init_tracing();

    let config = match Config::from_env() {
        Ok(c) => c,
        Err(err) => {
            // Tracing is up, so surface the config error and exit non-zero.
            tracing::error!(%err, "failed to load configuration");
            std::process::exit(1);
        }
    };

    let bind_addr: SocketAddr = match config.bind_addr.parse() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::error!(%err, bind_addr = %config.bind_addr, "invalid BIND_ADDR");
            std::process::exit(1);
        }
    };

    let db = match infra::db::connect(&config.database_url).await {
        Ok(pool) => pool,
        Err(err) => {
            tracing::error!(%err, "failed to connect to database");
            std::process::exit(1);
        }
    };

    if let Err(err) = infra::db::run_migrations(&db).await {
        tracing::error!(%err, "failed to run database migrations");
        std::process::exit(1);
    }
    tracing::info!("database migrations applied");

    let router = app::build_router(config, db);

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(%err, %bind_addr, "failed to bind listener");
            std::process::exit(1);
        }
    };

    tracing::info!(%bind_addr, "contract-scanner listening");

    if let Err(err) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!(%err, "server error");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("contract_scanner=debug,tower_http=info,info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
