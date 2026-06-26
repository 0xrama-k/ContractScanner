//! Common finding model types (Section 6) and the score breakdown (Section 8).
//!
//! These are deterministic, analyzer-agnostic value types shared by the
//! normalizer, scorer, and report generator.

// Several helpers/fields are consumed by later milestones (normalizer, report).
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Product severity. Serializes to "Critical", "High", ... (Section 6 wording).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Severity {
    /// Base severity value used by the score formula (Section 8).
    pub fn base_value(self) -> f64 {
        match self {
            Severity::Critical => 10.0,
            Severity::High => 8.0,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Informational => 1.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Informational => "Informational",
        }
    }

    /// Map a final score to a severity band (Section 8).
    pub fn from_final_score(score: f64) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score >= 2.0 {
            Severity::Low
        } else {
            Severity::Informational
        }
    }
}

/// Product confidence (mirrors Slither confidence in V1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    /// Confidence factor used by the score formula (Section 8).
    pub fn factor(self) -> f64 {
        match self {
            Confidence::High => 0.9,
            Confidence::Medium => 0.6,
            Confidence::Low => 0.3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
        }
    }
}

/// Deterministic score breakdown stored on each finding (the `score` object).
/// Field names are the agreed seam contract (open-seam-decisions).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub base_severity: f64,
    pub confidence: f64,
    pub exploitability: f64,
    pub asset_impact: f64,
    pub final_score: f64,
    pub final_severity: Severity,
}
