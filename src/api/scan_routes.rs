use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::Value;

use crate::app::AppState;
use crate::error::AppError;
use crate::models::dto::{CreateScanRequest, CreateScanResponse, ScanStatusResponse};
use crate::services::scan_service;
use crate::util;

/// `POST /api/scans` — create a scan (returns 201 with the payment block).
pub async fn create_scan(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateScanRequest>,
) -> Result<(StatusCode, Json<CreateScanResponse>), AppError> {
    let ip = client_ip(&headers, addr);
    let ip_hash = util::ip_hash(&state.config.ip_hash_salt, &ip);
    let resp = scan_service::create_scan(&state, &ip_hash, req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

/// Best-effort client IP: trust `X-Forwarded-For`/`X-Real-IP` when present
/// (deployments behind a proxy), else the socket peer address.
fn client_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let t = first.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    if let Some(xr) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let t = xr.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    addr.ip().to_string()
}

/// `GET /api/scans/{scan_id}` — current status.
pub async fn get_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanStatusResponse>, AppError> {
    let resp = scan_service::get_status(&state, &scan_id).await?;
    Ok(Json(resp))
}

/// `GET /api/scans/{scan_id}/report` — the full UI/JSON report.
pub async fn get_report(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(scan_service::get_report(&state, &scan_id).await?))
}

/// `GET /api/scans/{scan_id}/export/json` — machine-readable report (same shape).
pub async fn export_json(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(scan_service::get_report(&state, &scan_id).await?))
}

/// `GET /api/scans/{scan_id}/export/markdown` — `{ filename, content }`.
pub async fn export_markdown(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(scan_service::export_markdown(&state, &scan_id).await?))
}
