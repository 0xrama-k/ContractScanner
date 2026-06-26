//! LLM explanation layer (Section 4). The LLM is a bounded reporting layer:
//! it only writes report text for finding IDs the backend already produced. It
//! never creates findings or changes severity/confidence/score/location.
//!
//! Any failure (transport, bad JSON, etc.) becomes an LLM_FAILED warning and the
//! report falls back to Slither-only text — the scan never fails because of the LLM.

#![allow(dead_code)]

use std::collections::HashSet;

use serde::Serialize;
use serde_json::{json, Value};

use crate::infra::llm_client::LlmClient;
use crate::models::finding::Finding;
use crate::models::metadata::ContractMetadata;

#[derive(Debug, Clone, Serialize)]
pub struct RiskArea {
    pub area: String,
    pub based_on_finding_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct EnrichResult {
    pub contract_summary: String,
    pub main_risk_areas: Vec<RiskArea>,
    pub warnings: Vec<String>,
}

const SYSTEM_PROMPT: &str = "You are a bounded reporting layer for a Solidity security scanner. \
You DO NOT detect vulnerabilities. You only write developer-friendly report text for the \
Slither findings provided to you. Rules: use ONLY the provided finding IDs; never invent new \
findings or IDs; never change severity, confidence, status, score, or location; do not claim \
something is vulnerable unless tied to a provided finding; do not rewrite the whole contract \
(give fix suggestions, not full patches). Respond with a SINGLE JSON object ONLY, no prose, no \
markdown fences, with exactly this shape: \
{\"contract_summary\": string, \"main_risk_areas\": [{\"area\": string, \"based_on_finding_ids\": [string]}], \
\"finding_explanations\": [{\"finding_id\": string, \"summary\": string, \"technical_details\": string, \
\"exploit_scenario\": string, \"fix_suggestion\": string, \"false_positive_note\": string}]}";

const LLM_FAILED_WARNING: &str =
    "LLM explanations could not be completed. Slither findings are still available.";

/// Enrich findings in place with LLM text and return the contract-level summary,
/// risk areas, and any warnings. Never panics; never propagates errors.
pub async fn enrich(
    client: &LlmClient,
    source_char_limit: usize,
    source: &str,
    metadata: &ContractMetadata,
    findings: &mut [Finding],
) -> EnrichResult {
    if findings.is_empty() {
        return EnrichResult::default();
    }

    let user = build_input(source, source_char_limit, metadata, findings);

    match client.chat(SYSTEM_PROMPT, &user).await {
        Ok(content) => match parse_and_apply(&content, findings) {
            Some(result) => result,
            None => fallback(),
        },
        Err(e) => {
            tracing::warn!(error = %e, "LLM call failed; using Slither-only text");
            fallback()
        }
    }
}

fn fallback() -> EnrichResult {
    EnrichResult {
        warnings: vec![LLM_FAILED_WARNING.to_string()],
        ..Default::default()
    }
}

fn build_input(
    source: &str,
    char_limit: usize,
    metadata: &ContractMetadata,
    findings: &[Finding],
) -> String {
    let (policy, source_payload) = if source.len() <= char_limit {
        ("full_source", source.to_string())
    } else {
        ("windowed_excerpt", windowed_excerpt(source, findings))
    };

    let findings_json: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.as_str(),
                "confidence": f.confidence.as_str(),
                "location": {
                    "contract": f.location.contract,
                    "function": f.location.function,
                    "line_start": f.location.line_start,
                    "line_end": f.location.line_end,
                },
                "evidence": f.evidence,
                "slither_description": f.title,
            })
        })
        .collect();

    let input = json!({
        "contract_metadata": metadata,
        "source_excerpt_policy": policy,
        "source_code": source_payload,
        "findings": findings_json,
    });

    serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string())
}

/// Build a windowed excerpt: 30 lines around each finding, merged where overlapping.
fn windowed_excerpt(source: &str, findings: &[Finding]) -> String {
    const PAD: i32 = 30;
    let lines: Vec<&str> = source.lines().collect();
    let total = lines.len() as i32;

    let mut ranges: Vec<(i32, i32)> = findings
        .iter()
        .filter_map(|f| {
            let s = f.location.line_start?;
            let e = f.location.line_end.unwrap_or(s);
            Some(((s - PAD).max(1), (e + PAD).min(total)))
        })
        .collect();
    ranges.sort();

    let mut merged: Vec<(i32, i32)> = Vec::new();
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 + 1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }

    let mut out = String::new();
    for (s, e) in merged {
        out.push_str(&format!("// lines {s}-{e}\n"));
        for ln in s..=e {
            if let Some(line) = lines.get((ln - 1) as usize) {
                out.push_str(&format!("{ln}: {line}\n"));
            }
        }
        out.push_str("// ...\n");
    }
    out
}

/// Parse the model output and apply text to findings. Returns None on any parse
/// failure (caller falls back). Unknown finding IDs and disallowed fields are ignored.
fn parse_and_apply(content: &str, findings: &mut [Finding]) -> Option<EnrichResult> {
    let json_slice = extract_json_object(content)?;
    let v: Value = serde_json::from_str(json_slice).ok()?;

    let known: HashSet<String> = findings.iter().map(|f| f.id.clone()).collect();

    // Finding-level text — only for known IDs; only the allowed text fields.
    if let Some(arr) = v.get("finding_explanations").and_then(Value::as_array) {
        for item in arr {
            let Some(id) = item.get("finding_id").and_then(Value::as_str) else {
                continue;
            };
            if !known.contains(id) {
                continue; // ignore IDs the backend never produced
            }
            if let Some(f) = findings.iter_mut().find(|f| f.id == id) {
                set_if_present(item, "summary", &mut f.summary);
                set_if_present(item, "technical_details", &mut f.technical_details);
                set_if_present(item, "exploit_scenario", &mut f.exploit_scenario);
                set_if_present(item, "fix_suggestion", &mut f.fix_suggestion);
                set_if_present(item, "false_positive_note", &mut f.false_positive_note);
            }
        }
    }

    let contract_summary = v
        .get("contract_summary")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let main_risk_areas = v
        .get("main_risk_areas")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let area = a.get("area").and_then(Value::as_str)?.to_string();
                    let ids = a
                        .get("based_on_finding_ids")
                        .and_then(Value::as_array)
                        .map(|ids| {
                            ids.iter()
                                .filter_map(Value::as_str)
                                .filter(|id| known.contains(*id)) // drop unknown IDs
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(RiskArea {
                        area,
                        based_on_finding_ids: ids,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(EnrichResult {
        contract_summary,
        main_risk_areas,
        warnings: vec![],
    })
}

fn set_if_present(item: &Value, key: &str, target: &mut String) {
    if let Some(s) = item.get(key).and_then(Value::as_str) {
        if !s.trim().is_empty() {
            *target = s.to_string();
        }
    }
}

/// Extract the outermost JSON object from model output (handles stray prose or
/// markdown fences around the JSON).
fn extract_json_object(content: &str) -> Option<&str> {
    let start = content.find('{')?;
    let end = content.rfind('}')?;
    if end > start {
        Some(&content[start..=end])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{Confidence, Finding, Location, Severity};

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: "t".into(),
            category: "Reentrancy".into(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            status: "Detected".into(),
            sources: vec!["slither".into()],
            finding_fingerprint: "fp".into(),
            location: Location {
                file: None,
                contract: Some("Vault".into()),
                function: Some("withdraw".into()),
                line_start: Some(10),
                line_end: Some(12),
            },
            summary: String::new(),
            technical_details: String::new(),
            exploit_scenario: String::new(),
            fix_suggestion: String::new(),
            false_positive_note: String::new(),
            evidence: vec![],
            score: None,
            detector: "reentrancy-eth".into(),
        }
    }

    #[test]
    fn applies_known_ids_and_ignores_unknown() {
        let mut findings = vec![finding("FIND-001")];
        let content = r#"```json
        {
          "contract_summary": "A vault.",
          "main_risk_areas": [{"area": "External calls", "based_on_finding_ids": ["FIND-001", "FIND-999"]}],
          "finding_explanations": [
            {"finding_id": "FIND-001", "summary": "S", "fix_suggestion": "F"},
            {"finding_id": "FIND-999", "summary": "should be ignored"}
          ]
        }
        ```"#;
        let result = parse_and_apply(content, &mut findings).expect("parsed");
        assert_eq!(result.contract_summary, "A vault.");
        assert_eq!(findings[0].summary, "S");
        assert_eq!(findings[0].fix_suggestion, "F");
        // Unknown FIND-999 dropped from risk areas.
        assert_eq!(result.main_risk_areas[0].based_on_finding_ids, vec!["FIND-001"]);
    }

    #[test]
    fn malformed_output_returns_none() {
        let mut findings = vec![finding("FIND-001")];
        assert!(parse_and_apply("not json at all", &mut findings).is_none());
    }
}
