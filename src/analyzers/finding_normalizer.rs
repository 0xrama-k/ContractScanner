//! Finding normalization + deduplication (Sections 5, 6, 7).
//!
//! Owns all conversion from Slither-specific output to product-level findings:
//! detector -> category, impact -> severity, confidence -> confidence, stable
//! `FIND-NNN` ids, fingerprints, location normalization, and dedup/merge.
//! Scoring is a separate step (RiskScorer); `score` is left `None` here.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::models::finding::{Confidence, Finding, Location, Severity};
use crate::models::raw_finding::RawSlitherFinding;
use crate::util;

/// Normalize and deduplicate raw Slither findings into the common model.
pub fn normalize(raws: Vec<RawSlitherFinding>) -> Vec<Finding> {
    // 1. Merge duplicates. Key = category + contract + function + coarse line bucket
    //    (Section 7 "approximate_line_range"; bucket groups nearby lines).
    let mut merged: BTreeMap<DedupKey, Merged> = BTreeMap::new();

    for raw in raws {
        let category = map_category(&raw.detector);
        let key = DedupKey {
            category: category.clone(),
            contract: raw.contract.clone().unwrap_or_default(),
            function: raw.function.clone().unwrap_or_default(),
            line_bucket: raw.line_start.unwrap_or(0) / 10,
        };

        let entry = merged.entry(key).or_insert_with(|| Merged {
            detector: raw.detector.clone(),
            title: raw.check.clone(),
            category,
            severity: map_severity(&raw.impact),
            confidence: map_confidence(&raw.confidence),
            file: raw.file.clone(),
            contract: raw.contract.clone(),
            function: raw.function.clone(),
            line_start: raw.line_start,
            line_end: raw.line_end,
            evidence: Vec::new(),
        });

        // Keep all evidence snippets from merged findings (Section 7).
        for e in raw.evidence {
            if !entry.evidence.contains(&e) {
                entry.evidence.push(e);
            }
        }
        // Widen the line span to cover all merged elements.
        entry.line_start = min_opt(entry.line_start, raw.line_start);
        entry.line_end = max_opt(entry.line_end, raw.line_end);
        // Keep the highest severity/confidence seen for the merged group.
        entry.severity = max_severity(entry.severity, map_severity(&raw.impact));
        entry.confidence = max_confidence(entry.confidence, map_confidence(&raw.confidence));
    }

    // 2. Stable order for id assignment: severity desc, then location.
    let mut items: Vec<Merged> = merged.into_values().collect();
    items.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.contract.cmp(&b.contract))
            .then_with(|| a.function.cmp(&b.function))
            .then_with(|| a.line_start.cmp(&b.line_start))
    });

    // 3. Build findings with FIND-NNN ids and fingerprints.
    items
        .into_iter()
        .enumerate()
        .map(|(i, m)| {
            let fingerprint = fingerprint(&m);
            Finding {
                id: format!("FIND-{:03}", i + 1),
                title: m.title,
                category: m.category,
                severity: m.severity,
                confidence: m.confidence,
                status: "Detected".to_string(),
                sources: vec!["slither".to_string()],
                finding_fingerprint: fingerprint,
                location: Location {
                    file: m.file,
                    contract: m.contract,
                    function: m.function,
                    line_start: m.line_start,
                    line_end: m.line_end,
                },
                summary: String::new(),
                technical_details: String::new(),
                exploit_scenario: String::new(),
                fix_suggestion: String::new(),
                false_positive_note: String::new(),
                evidence: m.evidence,
                score: None,
                detector: m.detector,
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DedupKey {
    category: String,
    contract: String,
    function: String,
    line_bucket: i32,
}

struct Merged {
    detector: String,
    title: String,
    category: String,
    severity: Severity,
    confidence: Confidence,
    file: Option<String>,
    contract: Option<String>,
    function: Option<String>,
    line_start: Option<i32>,
    line_end: Option<i32>,
    evidence: Vec<String>,
}

/// fingerprint = hash(detector + contract + function + line_start + evidence) (Section 6).
fn fingerprint(m: &Merged) -> String {
    let material = format!(
        "{}|{}|{}|{}|{}",
        m.detector,
        m.contract.as_deref().unwrap_or(""),
        m.function.as_deref().unwrap_or(""),
        m.line_start.unwrap_or(0),
        m.evidence.join(";"),
    );
    util::sha256_hex(&material)
}

/// Detector -> product category (Section 4). Specific before generic.
pub fn map_category(detector: &str) -> String {
    let d = detector.to_ascii_lowercase();
    let cat = if d.starts_with("reentrancy") {
        "Reentrancy"
    } else if d.starts_with("unchecked") {
        "Transfer Safety"
    } else if d == "tx-origin" {
        "Access Control"
    } else if d == "controlled-delegatecall" {
        "Dangerous EVM / Access Control"
    } else if d.contains("delegatecall") {
        "Dangerous EVM"
    } else if d.contains("timestamp") {
        "Randomness"
    } else if d.contains("assembly") {
        "Dangerous EVM"
    } else if d.contains("solc-version") {
        "Code Quality"
    } else {
        "Code Quality"
    };
    cat.to_string()
}

pub fn map_severity(impact: &str) -> Severity {
    match impact.trim().to_ascii_lowercase().as_str() {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

pub fn map_confidence(confidence: &str) -> Confidence {
    match confidence.trim().to_ascii_lowercase().as_str() {
        "high" => Confidence::High,
        "medium" => Confidence::Medium,
        _ => Confidence::Low,
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Informational => 4,
    }
}

fn max_severity(a: Severity, b: Severity) -> Severity {
    if severity_rank(a) <= severity_rank(b) {
        a
    } else {
        b
    }
}

fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    }
}

fn max_confidence(a: Confidence, b: Confidence) -> Confidence {
    if confidence_rank(a) <= confidence_rank(b) {
        a
    } else {
        b
    }
}

fn min_opt(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn max_opt(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(detector: &str, impact: &str, conf: &str, func: &str, line: i32, ev: &str) -> RawSlitherFinding {
        RawSlitherFinding {
            detector: detector.to_string(),
            check: format!("{detector} check"),
            impact: impact.to_string(),
            confidence: conf.to_string(),
            description: String::new(),
            markdown: String::new(),
            file: Some("Contract.sol".to_string()),
            contract: Some("Vault".to_string()),
            function: Some(func.to_string()),
            line_start: Some(line),
            line_end: Some(line + 1),
            evidence: vec![ev.to_string()],
        }
    }

    #[test]
    fn maps_category_severity_confidence_and_sets_detected() {
        let out = normalize(vec![raw("reentrancy-eth", "High", "High", "withdraw", 42, "a")]);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.id, "FIND-001");
        assert_eq!(f.category, "Reentrancy");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.status, "Detected");
        assert_eq!(f.sources, vec!["slither".to_string()]);
        assert!(f.finding_fingerprint.starts_with("sha256:"));
        assert!(f.score.is_none());
    }

    #[test]
    fn merges_duplicates_in_same_function_and_keeps_all_evidence() {
        let out = normalize(vec![
            raw("reentrancy-eth", "High", "High", "withdraw", 42, "call A"),
            raw("reentrancy-eth", "High", "High", "withdraw", 43, "call B"),
        ]);
        assert_eq!(out.len(), 1, "same category/contract/function/near-line should merge");
        assert_eq!(out[0].evidence, vec!["call A".to_string(), "call B".to_string()]);
    }

    #[test]
    fn distinct_categories_are_not_merged_and_ordered_by_severity() {
        let out = normalize(vec![
            raw("solc-version", "Informational", "High", "", 1, "pragma"),
            raw("reentrancy-eth", "High", "High", "withdraw", 42, "call"),
        ]);
        assert_eq!(out.len(), 2);
        // Higher severity first -> FIND-001 is the reentrancy finding.
        assert_eq!(out[0].id, "FIND-001");
        assert_eq!(out[0].category, "Reentrancy");
        assert_eq!(out[1].category, "Code Quality");
    }
}
