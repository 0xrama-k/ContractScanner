use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use crate::app::AppState;
use crate::error::AppError;
use crate::models::dto::{CreateScanRequest, CreateScanResponse, ScanStatusResponse};
use crate::services::scan_service;

/// `POST /api/scans` — create a scan (returns 201 with the payment block).
pub async fn create_scan(
    State(state): State<AppState>,
    Json(req): Json<CreateScanRequest>,
) -> Result<(StatusCode, Json<CreateScanResponse>), AppError> {
    let resp = scan_service::create_scan(&state, req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
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
