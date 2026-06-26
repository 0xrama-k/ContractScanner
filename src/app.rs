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

/// Shared application state handed to every handler.
///
/// Holds process-wide singletons (config + DB pool now; watcher, limiter later).
#[derive(Clone)]
pub struct AppState {
    // Read by handlers starting in the next milestone (scan endpoints).
    #[allow(dead_code)]
    pub config: Arc<Config>,
    #[allow(dead_code)]
    pub db: PgPool,
}

/// Build the full application router with shared state and middleware.
pub fn build_router(config: Config, db: PgPool) -> Router {
    let state = AppState {
        config: Arc::new(config),
        db,
    };

    Router::new()
        .route("/health", get(api::health::health))
        .route("/api/scans", post(api::scan_routes::create_scan))
        .route("/api/scans/:scan_id", get(api::scan_routes::get_scan))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        // V1 frontend is a separate origin (Section "missing points": CORS).
        // Permissive for now; tighten to the real frontend origin before deploy.
        .layer(CorsLayer::permissive())
}
