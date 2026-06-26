use axum::Json;
use serde_json::{json, Value};

/// Liveness/readiness probe. Returns 200 with a small JSON body.
pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
