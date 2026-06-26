//! Lightweight contract metadata produced by preprocessing (Section 5).
//! Used by the UI, the LLM summary, and the report generator.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub filename: String,
    pub language: String,
    pub pragma: Option<String>,
    pub contracts: Vec<String>,
    pub functions: Vec<String>,
    pub imports: Vec<String>,
    /// Populated later if Slither compilation shows required files are missing.
    pub unresolved_imports: Vec<String>,
    pub line_count: usize,
    pub source_hash: String,
}
