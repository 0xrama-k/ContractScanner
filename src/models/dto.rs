use serde::{Deserialize, Serialize};

use super::scan::InputType;

/// `POST /api/scans` request body (Section 13).
#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub input_type: InputType,
    /// Required for `uploaded_file`; optional label for pasted code.
    pub filename: Option<String>,
    pub source_code: String,
}

/// `POST /api/scans` response: scan created, awaiting payment (Section 21).
#[derive(Debug, Serialize)]
pub struct CreateScanResponse {
    pub scan_id: String,
    pub status: String,
    pub message: String,
    pub payment: PaymentBlock,
}

/// On-chain payment instructions returned with a freshly created scan.
#[derive(Debug, Serialize)]
pub struct PaymentBlock {
    /// `null` while developing under `PAYMENT_BYPASS` with no contract deployed.
    pub contract_address: Option<String>,
    pub chain_id: i64,
    /// The scan id encoded as bytes32 for `pay(bytes32 scanId)`.
    pub scan_id_bytes32: String,
    pub price_wei: String,
    /// RFC3339 instant after which the scan expires if unpaid.
    pub expires_at: String,
    /// True when the gate is bypassed (dev): the scan starts without payment.
    pub bypassed: bool,
}

/// `GET /api/scans/{id}` response (Section 13).
#[derive(Debug, Serialize)]
pub struct ScanStatusResponse {
    pub scan_id: String,
    pub status: String,
    pub current_step: String,
    pub progress: u8,
    pub created_at: String,
    pub updated_at: String,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ScanErrorDetail>,
    /// Present while the scan is awaiting payment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<PaymentBlock>,
}

/// Inline error detail on a failed scan's status response (Section 13).
#[derive(Debug, Serialize)]
pub struct ScanErrorDetail {
    pub code: String,
    pub message: String,
}
