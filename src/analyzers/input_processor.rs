//! Cheap input validation (Section 13). Goal: reject obviously-invalid input
//! without rejecting valid Solidity. Final authority on compilability is Slither.

use crate::error::{AppError, ErrorCode};
use crate::models::dto::CreateScanRequest;
use crate::models::scan::InputType;

/// Max accepted source size (Section 15): 1 MB.
pub const MAX_FILE_BYTES: usize = 1_000_000;
/// Max accepted line count (Section 15).
pub const MAX_LINES: usize = 5000;

pub fn validate(req: &CreateScanRequest) -> Result<(), AppError> {
    let src = &req.source_code;

    // Hard rejects (Section 13).
    if src.trim().is_empty() {
        return Err(AppError::new(ErrorCode::EmptyInput, "Input is empty."));
    }
    if src.len() > MAX_FILE_BYTES {
        return Err(AppError::new(
            ErrorCode::FileTooLarge,
            "Source exceeds the 1 MB limit.",
        ));
    }
    if src.lines().count() > MAX_LINES {
        return Err(AppError::new(
            ErrorCode::FileTooLarge,
            "Source exceeds the 5000-line limit.",
        ));
    }
    if matches!(req.input_type, InputType::UploadedFile) {
        let is_sol = req
            .filename
            .as_deref()
            .map(|f| f.to_ascii_lowercase().ends_with(".sol"))
            .unwrap_or(false);
        if !is_sol {
            return Err(AppError::new(
                ErrorCode::UnsupportedFileType,
                "Uploaded file must be a .sol file.",
            ));
        }
    }

    // Soft Solidity heuristic (lenient): only reject if it clearly is not Solidity.
    if !looks_like_solidity(src) {
        return Err(AppError::new(
            ErrorCode::InvalidSolidityInput,
            "Input does not look like a valid Solidity contract.",
        ));
    }

    Ok(())
}

fn looks_like_solidity(src: &str) -> bool {
    let lower = src.to_ascii_lowercase();
    lower.contains("pragma solidity")
        || lower.contains("contract ")
        || lower.contains("library ")
        || lower.contains("interface ")
        || lower.contains("abstract contract")
}
