use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::api;
use crate::infra::config::Config;
use crate::infra::llm_client::LlmClient;
use crate::infra::rate_limit::Limiter;
use crate::infra::slither_runner::SlitherRunner;

/// Shared application state handed to every handler.
///
/// Holds process-wide singletons (config, DB pool, Slither runner, limiter, LLM).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub slither: Arc<SlitherRunner>,
    pub limiter: Arc<Limiter>,
    /// None when no LLM API key is configured (reports use Slither-only text).
    pub llm: Option<Arc<LlmClient>>,
}

/// Build the full application router with shared state and middleware.
pub fn build_router(
    config: Config,
    db: PgPool,
    slither: Arc<SlitherRunner>,
    limiter: Arc<Limiter>,
    llm: Option<Arc<LlmClient>>,
) -> Router {
    let state = AppState {
        config: Arc::new(config),
        db,
        slither,
        limiter,
        llm,
    };

    Router::new()
        .route("/health", get(api::health::health))
        .route("/api/scans", post(api::scan_routes::create_scan))
        .route("/api/scans/:scan_id", get(api::scan_routes::get_scan))
        .route(
            "/api/scans/:scan_id/report",
            get(api::scan_routes::get_report),
        )
        .route(
            "/api/scans/:scan_id/export/json",
            get(api::scan_routes::export_json),
        )
        .route(
            "/api/scans/:scan_id/export/markdown",
            get(api::scan_routes::export_markdown),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        // V1 frontend is a separate origin (Section "missing points": CORS).
        // Permissive for now; tighten to the real frontend origin before deploy.
        .layer(CorsLayer::permissive())
}
