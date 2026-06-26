use serde::{Deserialize, Serialize};

/// Scan lifecycle status (Section 11). Serializes to the exact wire strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    AwaitingPayment,
    Queued,
    Running,
    AnalyzingSlither,
    AnalyzingLlm,
    Scoring,
    ReportReady,
    Failed,
}

impl ScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanStatus::AwaitingPayment => "awaiting_payment",
            ScanStatus::Queued => "queued",
            ScanStatus::Running => "running",
            ScanStatus::AnalyzingSlither => "analyzing_slither",
            ScanStatus::AnalyzingLlm => "analyzing_llm",
            ScanStatus::Scoring => "scoring",
            ScanStatus::ReportReady => "report_ready",
            ScanStatus::Failed => "failed",
        }
    }

    /// Coarse progress percentage shown in the status API. Keeps frontend and
    /// backend agreeing on a single mapping (one of the blueprint's open items).
    pub fn progress(self) -> u8 {
        match self {
            ScanStatus::AwaitingPayment => 0,
            ScanStatus::Queued => 10,
            ScanStatus::Running => 20,
            ScanStatus::AnalyzingSlither => 45,
            ScanStatus::AnalyzingLlm => 70,
            ScanStatus::Scoring => 85,
            ScanStatus::ReportReady => 100,
            ScanStatus::Failed => 100,
        }
    }

    /// Human-readable step label for the status API.
    pub fn current_step(self) -> &'static str {
        match self {
            ScanStatus::AwaitingPayment => "Waiting for payment",
            ScanStatus::Queued => "Queued",
            ScanStatus::Running => "Starting analysis",
            ScanStatus::AnalyzingSlither => "Running Slither static analysis",
            ScanStatus::AnalyzingLlm => "Generating explanations",
            ScanStatus::Scoring => "Scoring findings",
            ScanStatus::ReportReady => "Report ready",
            ScanStatus::Failed => "Scan failed",
        }
    }

    // Used by the polling/lifecycle logic that lands with the real pipeline.
    #[allow(dead_code)]
    pub fn is_terminal(self) -> bool {
        matches!(self, ScanStatus::ReportReady | ScanStatus::Failed)
    }
}

/// How the source was supplied (Section 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    PastedCode,
    UploadedFile,
}

impl InputType {
    pub fn as_str(self) -> &'static str {
        match self {
            InputType::PastedCode => "pasted_code",
            InputType::UploadedFile => "uploaded_file",
        }
    }
}
