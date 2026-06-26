//! Shared API error type and the single error envelope used by every endpoint.
//!
//! Wire shape (Section 13 of the blueprint):
//! ```json
//! { "error": { "code": "INVALID_SOLIDITY_INPUT", "message": "...", "details": { ... } } }
//! ```

// Many codes/helpers are defined ahead of their first use as the API grows.
#![allow(dead_code)]

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Stable, machine-readable error codes (Section 13). The string form is part of
/// the public API contract — do not rename without coordinating with frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidInput,
    InvalidSolidityInput,
    FileTooLarge,
    EmptyInput,
    UnsupportedFileType,
    DependencyMissing,
    UnresolvedImports,
    ScanNotFound,
    ScanNotReady,
    SlitherFailed,
    SlitherCompilationFailed,
    LlmFailed,
    ReportGenerationFailed,
    InternalError,
    RateLimited,
    TooManyConcurrentScans,
    PaymentNotReceived,
    PaymentUnderpaid,
    PaymentVerificationFailed,
}

impl ErrorCode {
    /// The wire string for this code.
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            InvalidInput => "INVALID_INPUT",
            InvalidSolidityInput => "INVALID_SOLIDITY_INPUT",
            FileTooLarge => "FILE_TOO_LARGE",
            EmptyInput => "EMPTY_INPUT",
            UnsupportedFileType => "UNSUPPORTED_FILE_TYPE",
            DependencyMissing => "DEPENDENCY_MISSING",
            UnresolvedImports => "UNRESOLVED_IMPORTS",
            ScanNotFound => "SCAN_NOT_FOUND",
            ScanNotReady => "SCAN_NOT_READY",
            SlitherFailed => "SLITHER_FAILED",
            SlitherCompilationFailed => "SLITHER_COMPILATION_FAILED",
            LlmFailed => "LLM_FAILED",
            ReportGenerationFailed => "REPORT_GENERATION_FAILED",
            InternalError => "INTERNAL_ERROR",
            RateLimited => "RATE_LIMITED",
            TooManyConcurrentScans => "TOO_MANY_CONCURRENT_SCANS",
            PaymentNotReceived => "PAYMENT_NOT_RECEIVED",
            PaymentUnderpaid => "PAYMENT_UNDERPAID",
            PaymentVerificationFailed => "PAYMENT_VERIFICATION_FAILED",
        }
    }

    /// HTTP status this code maps to.
    pub fn status(self) -> StatusCode {
        use ErrorCode::*;
        match self {
            InvalidInput
            | InvalidSolidityInput
            | EmptyInput
            | UnsupportedFileType
            | DependencyMissing
            | UnresolvedImports => StatusCode::BAD_REQUEST,
            FileTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ScanNotFound => StatusCode::NOT_FOUND,
            // Report requested before it is ready: conflict with current state.
            ScanNotReady => StatusCode::CONFLICT,
            PaymentNotReceived | PaymentUnderpaid => StatusCode::PAYMENT_REQUIRED,
            RateLimited | TooManyConcurrentScans => StatusCode::TOO_MANY_REQUESTS,
            // Analyzer/pipeline failures are surfaced as server-side errors.
            SlitherFailed
            | SlitherCompilationFailed
            | LlmFailed
            | ReportGenerationFailed
            | PaymentVerificationFailed
            | InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// An API error that renders as the standard error envelope.
#[derive(Debug)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<Value>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Attach a structured `details` object (Section 13).
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ScanNotFound, message)
    }

    /// Generic internal error. The public message is intentionally vague; log the
    /// real cause at the call site rather than leaking it to the client.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut error_obj = json!({
            "code": self.code.as_str(),
            "message": self.message,
        });

        if let Some(details) = self.details {
            error_obj["details"] = details;
        }

        let body = Json(json!({ "error": error_obj }));
        (self.code.status(), body).into_response()
    }
}

/// Convenience alias for handlers that return either a success type or `AppError`.
pub type AppResult<T> = Result<T, AppError>;
