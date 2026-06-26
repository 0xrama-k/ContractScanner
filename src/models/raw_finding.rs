//! Raw Slither finding (Section 5): the small internal model the Slither adapter
//! produces from Slither JSON, *before* normalization.
//!
//! Seam decision: the adapter preserves the raw detector name and original
//! Slither severity/confidence and does NOT map to product categories — that is
//! the normalizer's job (resolves the Section 5 vs 17 ownership overlap).

// Constructed by the Slither adapter (Docker milestone); used by the normalizer.
#![allow(dead_code)]

/// A single Slither detector result, location best-effort.
#[derive(Debug, Clone)]
pub struct RawSlitherFinding {
    /// Raw detector id, e.g. `reentrancy-eth`, `unchecked-lowlevel`.
    pub detector: String,
    /// Human-readable check name, used as the finding title.
    pub check: String,
    /// Slither impact: `High` | `Medium` | `Low` | `Informational`.
    pub impact: String,
    /// Slither confidence: `High` | `Medium` | `Low`.
    pub confidence: String,
    pub description: String,
    pub markdown: String,
    pub file: Option<String>,
    pub contract: Option<String>,
    pub function: Option<String>,
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub evidence: Vec<String>,
}
