use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::analyzers::{input_processor, llm_analyzer, pipeline, report_generator};
use crate::app::AppState;
use crate::error::{AppError, ErrorCode};
use crate::infra::llm_client::LlmClient;
use crate::infra::slither_runner::{SlitherError, SlitherRunner};
use crate::models::dto::{
    CreateScanRequest, CreateScanResponse, PaymentBlock, ScanErrorDetail, ScanStatusResponse,
};
use crate::models::scan::ScanStatus;
use crate::repositories::{finding_repository, report_repository, scan_repository};
use crate::repositories::scan_repository::NewScan;
use crate::util;

/// Create a scan: validate input, persist as `awaiting_payment`, and return the
/// payment block. Under `PAYMENT_BYPASS`, also kick off the real pipeline.
pub async fn create_scan(
    state: &AppState,
    ip_hash: &str,
    req: CreateScanRequest,
) -> Result<CreateScanResponse, AppError> {
    input_processor::validate(&req)?;

    let source_hash = util::sha256_hex(&req.source_code);

    // Idempotency: a recent identical submission returns the existing scan and
    // does NOT consume rate-limit quota or start a second scan (Section 15).
    if state.config.idempotency_window_secs > 0 {
        if let Some(existing) = scan_repository::find_recent_by_hash(
            &state.db,
            ip_hash,
            &source_hash,
            state.config.idempotency_window_secs,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "idempotency lookup failed");
            AppError::internal("Failed to create scan.")
        })? {
            let payment =
                build_payment_block(state, existing.id, existing.created_at, &existing.price_wei);
            return Ok(CreateScanResponse {
                scan_id: existing.id.to_string(),
                status: existing.status,
                message: "Duplicate submission; returning the existing scan.".to_string(),
                payment,
            });
        }
    }

    // Per-IP rate limit.
    if let Err(rl) = state.limiter.check_and_record(ip_hash) {
        return Err(AppError::new(
            ErrorCode::RateLimited,
            "Too many scans from this client. Please try again later.",
        )
        .with_details(serde_json::json!({ "retry_after_secs": rl.retry_after_secs })));
    }

    let new = NewScan {
        status: ScanStatus::AwaitingPayment,
        input_type: req.input_type.as_str(),
        filename: req.filename.as_deref(),
        source_hash: &source_hash,
        ip_hash: Some(ip_hash),
        price_wei: &state.config.scan_price_wei,
        pending_source: &req.source_code,
    };

    let created = scan_repository::create_scan(&state.db, new)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create_scan db insert failed");
            AppError::internal("Failed to create scan.")
        })?;

    let payment =
        build_payment_block(state, created.id, created.created_at, &state.config.scan_price_wei);

    let bypass = state.config.payment_bypass;
    if bypass {
        // Dev only: start the real pipeline immediately, no on-chain payment.
        spawn_pipeline(state, created.id);
    }

    Ok(CreateScanResponse {
        scan_id: created.id.to_string(),
        status: ScanStatus::AwaitingPayment.as_str().to_string(),
        message: if bypass {
            "Scan created (payment bypassed in dev). Analysis starting.".to_string()
        } else {
            "Scan created. Complete payment to start analysis.".to_string()
        },
        payment,
    })
}

pub async fn get_status(state: &AppState, scan_id: &str) -> Result<ScanStatusResponse, AppError> {
    let id = parse_id(scan_id)?;

    let row = scan_repository::get_status(&state.db, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get_status db query failed");
            AppError::internal("Failed to load scan.")
        })?
        .ok_or_else(|| AppError::not_found("Scan not found."))?;

    let status = parse_status(&row.status);

    let payment = if status == ScanStatus::AwaitingPayment {
        Some(build_payment_block(state, id, row.created_at, &row.price_wei))
    } else {
        None
    };

    let error = if status == ScanStatus::Failed {
        row.error_message.clone().map(|message| ScanErrorDetail {
            code: row
                .error_code
                .clone()
                .unwrap_or_else(|| ErrorCode::InternalError.as_str().to_string()),
            message,
        })
    } else {
        None
    };

    Ok(ScanStatusResponse {
        scan_id: id.to_string(),
        status: row.status,
        current_step: status.current_step().to_string(),
        progress: status.progress(),
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
        warnings: vec![],
        error,
        payment,
    })
}

/// The stored JSON report (Section 13 UI report shape). Used for both the
/// `/report` endpoint and the JSON export.
pub async fn get_report(state: &AppState, scan_id: &str) -> Result<Value, AppError> {
    let id = parse_id(scan_id)?;
    let status = load_status(state, id).await?;

    if status != ScanStatus::ReportReady {
        return Err(AppError::new(
            ErrorCode::ScanNotReady,
            not_ready_message(status),
        ));
    }

    let stored = report_repository::load_report(&state.db, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "load_report failed");
            AppError::internal("Failed to load report.")
        })?
        .ok_or_else(|| AppError::internal("Report is missing for a ready scan."))?;

    serde_json::from_str(&stored.json_report)
        .map_err(|_| AppError::internal("Stored report is not valid JSON."))
}

/// Markdown export: `{ "filename", "content" }` (Section 13).
pub async fn export_markdown(state: &AppState, scan_id: &str) -> Result<Value, AppError> {
    let id = parse_id(scan_id)?;
    let status = load_status(state, id).await?;

    if status != ScanStatus::ReportReady {
        return Err(AppError::new(
            ErrorCode::ScanNotReady,
            not_ready_message(status),
        ));
    }

    let stored = report_repository::load_report(&state.db, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "load_report failed");
            AppError::internal("Failed to load report.")
        })?
        .ok_or_else(|| AppError::internal("Report is missing for a ready scan."))?;

    Ok(serde_json::json!({
        "filename": "smart-contract-security-report.md",
        "content": stored.markdown_report,
    }))
}

// --- helpers ---

fn parse_id(scan_id: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(scan_id).map_err(|_| AppError::not_found("Scan not found."))
}

async fn load_status(state: &AppState, id: Uuid) -> Result<ScanStatus, AppError> {
    let row = scan_repository::get_status(&state.db, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get_status db query failed");
            AppError::internal("Failed to load scan.")
        })?
        .ok_or_else(|| AppError::not_found("Scan not found."))?;
    Ok(parse_status(&row.status))
}

fn not_ready_message(status: ScanStatus) -> &'static str {
    if status == ScanStatus::Failed {
        "Scan failed; no report is available."
    } else {
        "Report is not ready yet."
    }
}

fn build_payment_block(
    state: &AppState,
    id: Uuid,
    created_at: DateTime<Utc>,
    price_wei: &str,
) -> PaymentBlock {
    let expires_at = created_at + Duration::seconds(state.config.payment_window_secs);
    PaymentBlock {
        contract_address: state.config.payment_contract_address.clone(),
        chain_id: state.config.chain_id,
        scan_id_bytes32: util::uuid_to_bytes32(id),
        price_wei: price_wei.to_string(),
        expires_at: expires_at.to_rfc3339(),
        bypassed: state.config.payment_bypass,
    }
}

fn parse_status(s: &str) -> ScanStatus {
    match s {
        "awaiting_payment" => ScanStatus::AwaitingPayment,
        "queued" => ScanStatus::Queued,
        "running" => ScanStatus::Running,
        "analyzing_slither" => ScanStatus::AnalyzingSlither,
        "analyzing_llm" => ScanStatus::AnalyzingLlm,
        "scoring" => ScanStatus::Scoring,
        "report_ready" => ScanStatus::ReportReady,
        _ => ScanStatus::Failed,
    }
}

/// The live analyzer pipeline (replaces the earlier stub). Drives statuses,
/// runs Slither in the sandbox, normalizes/scores, and persists findings + report.
/// Spawn the analysis pipeline for a scan that is ready to run (bypass or paid).
fn spawn_pipeline(state: &AppState, scan_id: Uuid) {
    let db = state.db.clone();
    let slither = state.slither.clone();
    let sem = state.limiter.semaphore();
    let llm = state.llm.clone();
    let llm_char_limit = state.config.llm_source_char_limit;
    tokio::spawn(async move { run_pipeline(db, slither, sem, llm, llm_char_limit, scan_id).await });
}

/// Called by the PaymentWatcher when a confirmed `ScanPaid` log is observed.
/// Marks the scan paid + queued (idempotently via the WHERE clause) and starts
/// analysis. Returns true only if this call performed the transition.
pub async fn on_payment_observed(
    state: &AppState,
    scan_id: Uuid,
    payer: &str,
    tx_hash: &str,
) -> bool {
    match scan_repository::mark_paid(&state.db, scan_id, payer, tx_hash).await {
        Ok(true) => {
            tracing::info!(%scan_id, payer, "payment observed; starting analysis");
            spawn_pipeline(state, scan_id);
            true
        }
        Ok(false) => false, // unknown scan, or already past awaiting_payment
        Err(e) => {
            tracing::error!(error = %e, %scan_id, "mark_paid failed");
            false
        }
    }
}

async fn run_pipeline(
    db: PgPool,
    slither: Arc<SlitherRunner>,
    sem: Arc<tokio::sync::Semaphore>,
    llm: Option<Arc<LlmClient>>,
    llm_char_limit: usize,
    scan_id: Uuid,
) {
    // -> queued -> running -> analyzing_slither
    if step_failed(scan_repository::set_status(&db, scan_id, ScanStatus::Queued).await, scan_id, "set queued") {
        return;
    }

    // Bound simultaneous sandbox runs (Section 15). Queues briefly if at capacity;
    // the permit is held for the duration of the scan.
    let _permit = match sem.acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            tracing::error!(%scan_id, "concurrency semaphore closed");
            fail(&db, scan_id, ErrorCode::InternalError, "Internal error.").await;
            return;
        }
    };

    // Load the transiently-stored source (cleared when analysis completes).
    let (filename, source) = match scan_repository::load_pending_source(&db, scan_id).await {
        Ok(Some(p)) => match p.source {
            Some(s) => (p.filename.unwrap_or_else(|| "Contract.sol".to_string()), s),
            None => {
                tracing::error!(%scan_id, "pending source missing at analysis start");
                fail(&db, scan_id, ErrorCode::InternalError, "Source unavailable for analysis.").await;
                return;
            }
        },
        Ok(None) => {
            tracing::error!(%scan_id, "scan not found at analysis start");
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, %scan_id, "failed to load pending source");
            fail(&db, scan_id, ErrorCode::InternalError, "Failed to load scan source.").await;
            return;
        }
    };

    if step_failed(scan_repository::begin_running(&db, scan_id).await, scan_id, "begin running") {
        return;
    }
    if step_failed(
        scan_repository::set_status(&db, scan_id, ScanStatus::AnalyzingSlither).await,
        scan_id,
        "set analyzing_slither",
    ) {
        return;
    }

    let mut outcome = match pipeline::analyze(slither.as_ref(), scan_id, &filename, &source).await {
        Ok(o) => o,
        Err(e) => {
            let (code, msg) = map_slither_error(&e);
            tracing::warn!(error = %e, %scan_id, "scan failed during analysis");
            fail(&db, scan_id, code, &msg).await;
            return;
        }
    };

    // LLM enrichment (bounded reporting layer; never fails the scan).
    let enrich = if let Some(client) = &llm {
        let _ = scan_repository::set_status(&db, scan_id, ScanStatus::AnalyzingLlm).await;
        llm_analyzer::enrich(
            client,
            llm_char_limit,
            &source,
            &outcome.metadata,
            &mut outcome.findings,
        )
        .await
    } else {
        llm_analyzer::EnrichResult::default()
    };

    let _ = scan_repository::set_status(&db, scan_id, ScanStatus::Scoring).await;

    if let Err(e) = finding_repository::insert_findings(&db, scan_id, &outcome.findings).await {
        tracing::error!(error = %e, %scan_id, "failed to persist findings");
        fail(&db, scan_id, ErrorCode::ReportGenerationFailed, "Failed to store findings.").await;
        return;
    }

    let report = report_generator::generate(
        scan_id,
        &outcome,
        &enrich.contract_summary,
        &enrich.main_risk_areas,
        &enrich.warnings,
    );
    let json_str = serde_json::to_string(&report.json_report).unwrap_or_else(|_| "{}".to_string());

    if let Err(e) =
        report_repository::upsert_report(&db, scan_id, &json_str, &report.markdown_report).await
    {
        tracing::error!(error = %e, %scan_id, "failed to store report");
        fail(&db, scan_id, ErrorCode::ReportGenerationFailed, "Failed to store report.").await;
        return;
    }

    let _ = scan_repository::set_overall_risk(&db, scan_id, outcome.overall_risk.as_str()).await;
    let _ = scan_repository::clear_pending_source(&db, scan_id).await;

    if let Err(e) =
        scan_repository::finish(&db, scan_id, ScanStatus::ReportReady, None, None).await
    {
        tracing::error!(error = %e, %scan_id, "failed to mark report_ready");
        return;
    }

    tracing::info!(%scan_id, findings = outcome.findings.len(), risk = outcome.overall_risk.as_str(), "scan report_ready");
}

fn step_failed(result: Result<(), sqlx::Error>, scan_id: Uuid, step: &str) -> bool {
    if let Err(e) = result {
        tracing::error!(error = %e, %scan_id, step, "pipeline status update failed");
        true
    } else {
        false
    }
}

async fn fail(db: &PgPool, scan_id: Uuid, code: ErrorCode, msg: &str) {
    let _ = scan_repository::clear_pending_source(db, scan_id).await;
    if let Err(e) =
        scan_repository::finish(db, scan_id, ScanStatus::Failed, Some(code.as_str()), Some(msg)).await
    {
        tracing::error!(error = %e, %scan_id, "failed to mark scan failed");
    }
}

fn map_slither_error(e: &SlitherError) -> (ErrorCode, String) {
    match e {
        SlitherError::Compilation(m) => (
            ErrorCode::SlitherCompilationFailed,
            format!("Slither could not compile the contract: {m}. For best results, upload a flattened Solidity file."),
        ),
        SlitherError::Timeout => (ErrorCode::SlitherFailed, "Slither timed out.".to_string()),
        SlitherError::NoOutput => (
            ErrorCode::SlitherFailed,
            "Slither produced no usable output.".to_string(),
        ),
        SlitherError::Docker(m) => (ErrorCode::SlitherFailed, format!("Sandbox error: {m}")),
        SlitherError::Parse(m) => (
            ErrorCode::SlitherFailed,
            format!("Could not parse Slither output: {m}"),
        ),
        SlitherError::Workspace(m) => (ErrorCode::InternalError, format!("Workspace error: {m}")),
    }
}
