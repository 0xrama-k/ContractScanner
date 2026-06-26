//! Deterministic risk scoring (Section 8).
//!
//! The backend owns all scoring: detector/category -> exploitability/asset
//! mapping, the weighted final-score formula, severity banding, the Critical
//! post-score escalation, and overall scan risk. The LLM never touches any of it.

// Public API consumed by the normalizer/report generator in later milestones.
#![allow(dead_code)]

use crate::models::finding::{Confidence, ScoreBreakdown, Severity};

/// Internal exploitability factor (not stored directly; folds into the score).
#[derive(Debug, Clone, Copy)]
enum Exploitability {
    High,
    Medium,
    Low,
}

impl Exploitability {
    fn factor(self) -> f64 {
        match self {
            Exploitability::High => 0.9,
            Exploitability::Medium => 0.6,
            Exploitability::Low => 0.3,
        }
    }
}

/// Internal asset-impact factor.
#[derive(Debug, Clone, Copy)]
enum AssetImpact {
    High,
    Medium,
    Low,
    None,
}

impl AssetImpact {
    fn factor(self) -> f64 {
        match self {
            AssetImpact::High => 0.9,
            AssetImpact::Medium => 0.6,
            AssetImpact::Low => 0.3,
            AssetImpact::None => 0.1,
        }
    }
}

/// Inputs the scorer needs from a normalized finding.
pub struct ScoreInput<'a> {
    /// Raw Slither detector name, e.g. `reentrancy-eth`, `unchecked-lowlevel`.
    pub detector: &'a str,
    /// Product severity (mapped from Slither impact) -> base severity value.
    pub severity: Severity,
    /// Product/Slither confidence.
    pub confidence: Confidence,
}

/// Detectors that may escalate to Critical when Slither confidence is High
/// (Section 8 "Critical reachability rule"). Tune as coverage grows.
const CRITICAL_ELIGIBLE: &[&str] = &[
    "reentrancy-eth",
    "reentrancy-no-eth",
    "controlled-delegatecall",
    "arbitrary-send-eth",
];

/// Compute the full score breakdown for one finding.
pub fn score(input: &ScoreInput) -> ScoreBreakdown {
    let (exploitability, asset_impact) = map_detector(input.detector, input.severity);

    let base_severity = input.severity.base_value();
    let confidence = input.confidence.factor();
    let exploitability = exploitability.factor();
    let asset_impact = asset_impact.factor();

    let mut final_score = (base_severity * 0.45)
        + (confidence * 10.0 * 0.20)
        + (exploitability * 10.0 * 0.20)
        + (asset_impact * 10.0 * 0.15);

    let mut final_severity = Severity::from_final_score(final_score);

    // Deterministic Critical escalation (Section 8). Independent of the LLM.
    if input.confidence == Confidence::High && CRITICAL_ELIGIBLE.contains(&input.detector) {
        final_severity = Severity::Critical;
        final_score = 9.0;
    }

    ScoreBreakdown {
        base_severity,
        confidence,
        exploitability,
        asset_impact,
        final_score,
        final_severity,
    }
}

/// Map a detector (falling back to severity) to exploitability/asset impact
/// per the Section 8 table. Specific detectors are matched before generic ones.
fn map_detector(detector: &str, severity: Severity) -> (Exploitability, AssetImpact) {
    use AssetImpact as A;
    use Exploitability as E;

    let d = detector.to_ascii_lowercase();

    if d.starts_with("reentrancy") {
        return (E::High, A::High);
    }
    if d == "tx-origin" {
        return (E::High, A::High);
    }
    if d == "controlled-delegatecall" {
        return (E::High, A::High);
    }
    if d.contains("delegatecall") {
        return (E::High, A::High);
    }
    if d.starts_with("unchecked") {
        return (E::Medium, A::Medium);
    }
    if d.contains("timestamp") {
        return (E::Medium, A::Medium);
    }
    if d.contains("assembly") {
        return (E::Medium, A::Medium);
    }
    if d.contains("solc-version") {
        return (E::Low, A::Low);
    }
    if d.starts_with("unused") {
        return (E::Low, A::None);
    }
    if d.contains("naming-convention") {
        return (E::Low, A::None);
    }

    // Fallback by severity when no detector-specific mapping applies.
    match severity {
        Severity::High => (E::Medium, A::High),
        Severity::Medium => (E::Medium, A::Medium),
        Severity::Low => (E::Low, A::Low),
        Severity::Informational => (E::Low, A::None),
        // Critical is never an input severity (it only arises from escalation).
        Severity::Critical => (E::High, A::High),
    }
}

/// Overall scan risk shown in the report summary (Section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallRisk {
    Critical,
    High,
    Medium,
    Low,
    NoMajorIssues,
}

impl OverallRisk {
    pub fn as_str(self) -> &'static str {
        match self {
            OverallRisk::Critical => "Critical",
            OverallRisk::High => "High",
            OverallRisk::Medium => "Medium",
            OverallRisk::Low => "Low",
            OverallRisk::NoMajorIssues => "No major issues found",
        }
    }
}

/// Derive overall risk from the final severities of all findings (Section 8).
pub fn overall_risk(severities: &[Severity]) -> OverallRisk {
    if severities.is_empty() {
        return OverallRisk::NoMajorIssues;
    }

    let critical = severities.iter().filter(|s| **s == Severity::Critical).count();
    let high = severities.iter().filter(|s| **s == Severity::High).count();
    let medium = severities.iter().filter(|s| **s == Severity::Medium).count();

    if critical > 0 {
        OverallRisk::Critical
    } else if high > 0 {
        OverallRisk::High
    } else if medium >= 3 {
        OverallRisk::Medium
    } else {
        OverallRisk::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
    }

    #[test]
    fn unchecked_medium_medium_scores_in_medium_band() {
        // base 5*0.45 + 0.6*10*0.2 + 0.6*10*0.2 + 0.6*10*0.15 = 2.25+1.2+1.2+0.9 = 5.55
        let s = score(&ScoreInput {
            detector: "unchecked-lowlevel",
            severity: Severity::Medium,
            confidence: Confidence::Medium,
        });
        approx(s.final_score, 5.55);
        assert_eq!(s.final_severity, Severity::Medium);
    }

    #[test]
    fn reentrancy_eth_high_confidence_escalates_to_critical() {
        let s = score(&ScoreInput {
            detector: "reentrancy-eth",
            severity: Severity::High,
            confidence: Confidence::High,
        });
        assert_eq!(s.final_severity, Severity::Critical);
        approx(s.final_score, 9.0);
    }

    #[test]
    fn reentrancy_without_high_confidence_does_not_escalate() {
        // reentrancy* -> (High expl, High asset); base 8, conf Medium 0.6.
        // 8*0.45 + 0.6*10*0.2 + 0.9*10*0.2 + 0.9*10*0.15 = 3.6+1.2+1.8+1.35 = 7.95 -> High
        let s = score(&ScoreInput {
            detector: "reentrancy-events",
            severity: Severity::High,
            confidence: Confidence::Medium,
        });
        approx(s.final_score, 7.95);
        assert_eq!(s.final_severity, Severity::High);
    }

    #[test]
    fn critical_eligible_but_low_confidence_does_not_escalate() {
        let s = score(&ScoreInput {
            detector: "controlled-delegatecall",
            severity: Severity::High,
            confidence: Confidence::Low,
        });
        assert_ne!(s.final_severity, Severity::Critical);
    }

    #[test]
    fn unknown_detector_uses_severity_fallback() {
        // fallback High -> (Medium expl, High asset); base 8, conf High 0.9.
        // 8*0.45 + 0.9*10*0.2 + 0.6*10*0.2 + 0.9*10*0.15 = 3.6+1.8+1.2+1.35 = 7.95
        let s = score(&ScoreInput {
            detector: "some-unmapped-detector",
            severity: Severity::High,
            confidence: Confidence::High,
        });
        approx(s.final_score, 7.95);
        assert_eq!(s.final_severity, Severity::High);
    }

    #[test]
    fn informational_scores_low_band() {
        let s = score(&ScoreInput {
            detector: "solc-version",
            severity: Severity::Informational,
            confidence: Confidence::Low,
        });
        // 1*0.45 + 0.3*10*0.2 + 0.3*10*0.2 + 0.3*10*0.15 = 0.45+0.6+0.6+0.45 = 2.1 -> Low
        approx(s.final_score, 2.1);
        assert_eq!(s.final_severity, Severity::Low);
    }

    #[test]
    fn overall_risk_rules() {
        assert_eq!(overall_risk(&[]), OverallRisk::NoMajorIssues);
        assert_eq!(
            overall_risk(&[Severity::Critical, Severity::Low]),
            OverallRisk::Critical
        );
        assert_eq!(
            overall_risk(&[Severity::High, Severity::Medium]),
            OverallRisk::High
        );
        assert_eq!(
            overall_risk(&[Severity::Medium, Severity::Medium, Severity::Medium]),
            OverallRisk::Medium
        );
        assert_eq!(
            overall_risk(&[Severity::Medium, Severity::Low]),
            OverallRisk::Low
        );
        assert_eq!(
            overall_risk(&[Severity::Informational]),
            OverallRisk::Low
        );
    }
}
