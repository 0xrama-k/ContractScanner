use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::analyzers::input_processor;
use crate::app::AppState;
use crate::error::{AppError, ErrorCode};
use crate::models::dto::{
    CreateScanRequest, CreateScanResponse, PaymentBlock, ScanErrorDetail, ScanStatusResponse,
};
use crate::models::scan::ScanStatus;
use crate::repositories::scan_repository::{self, NewScan};
use crate::util;

/// Create a scan: validate input, persist as `awaiting_payment`, and return the
/// payment block. Under `PAYMENT_BYPASS`, also kick off the (stub) pipeline.
pub async fn create_scan(
    state: &AppState,
    req: CreateScanRequest,
) -> Result<CreateScanResponse, AppError> {
    input_processor::validate(&req)?;

    let source_hash = util::sha256_hex(&req.source_code);

    let new = NewScan {
        status: ScanStatus::AwaitingPayment,
        input_type: req.input_type.as_str(),
        filename: req.filename.as_deref(),
        source_hash: &source_hash,
        ip_hash: None, // populated once rate limiting lands (Section 15)
        price_wei: &state.config.scan_price_wei,
    };

    let created = scan_repository::create_scan(&state.db, new)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "create_scan db insert failed");
            AppError::internal("Failed to create scan.")
        })?;

    let payment = build_payment_block(
        state,
        created.id,
        created.created_at,
        &state.config.scan_price_wei,
    );

    let bypass = state.config.payment_bypass;
    if bypass {
        // Dev only: start the pipeline immediately, no on-chain payment.
        let db = state.db.clone();
        let id = created.id;
        tokio::spawn(async move { run_pipeline_stub(db, id).await });
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
    let id = Uuid::parse_str(scan_id).map_err(|_| AppError::not_found("Scan not found."))?;

    let row = scan_repository::get_status(&state.db, id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get_status db query failed");
            AppError::internal("Failed to load scan.")
        })?
        .ok_or_else(|| AppError::not_found("Scan not found."))?;

    let status = parse_status(&row.status);

    let payment = if status == ScanStatus::AwaitingPayment {
        // Use the snapshotted price from the row, not current config.
        Some(build_payment_block(state, id, row.created_at, &row.price_wei))
    } else {
        None
    };

    let error = if status == ScanStatus::Failed {
        row.error_message.clone().map(|message| ScanErrorDetail {
            code: ErrorCode::InternalError.as_str().to_string(),
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

/// PLACEHOLDER pipeline. The real analyzer pipeline (Slither -> normalize ->
/// score -> LLM -> report) replaces this in later milestones. For now it just
/// walks the lifecycle so the bypass flow and status API are exercisable.
async fn run_pipeline_stub(db: PgPool, id: Uuid) {
    if let Err(e) = scan_repository::set_status(&db, id, ScanStatus::Queued).await {
        tracing::error!(error = %e, %id, "stub pipeline: set queued failed");
        return;
    }
    if let Err(e) = scan_repository::begin_running(&db, id).await {
        tracing::error!(error = %e, %id, "stub pipeline: begin running failed");
        return;
    }
    if let Err(e) = scan_repository::finish(&db, id, ScanStatus::ReportReady, None).await {
        tracing::error!(error = %e, %id, "stub pipeline: finish failed");
        return;
    }
    tracing::info!(%id, "stub pipeline complete (report_ready)");
}
