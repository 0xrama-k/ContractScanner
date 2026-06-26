//! Slither JSON adapter (Section 5): parse Slither `--json` output into the
//! internal `RawSlitherFinding` model. Navigates the JSON defensively (Slither's
//! shape varies by detector) and returns structured errors on failure.
//!
//! Seam rule: preserve the raw detector name and original impact/confidence;
//! do NOT map to product categories or score here (that is the normalizer/scorer).

#![allow(dead_code)]

use serde_json::Value;

use crate::models::raw_finding::RawSlitherFinding;

#[derive(Debug, thiserror::Error)]
pub enum SlitherParseError {
    #[error("slither output was not valid JSON: {0}")]
    MalformedJson(String),
    #[error("slither could not compile the contract: {0}")]
    CompilationFailed(String),
}

/// Parse the contents of `slither-output.json`.
pub fn parse(json_str: &str) -> Result<Vec<RawSlitherFinding>, SlitherParseError> {
    let root: Value = serde_json::from_str(json_str)
        .map_err(|e| SlitherParseError::MalformedJson(e.to_string()))?;

    // `success: false` means Slither could not compile/analyze the input.
    if root.get("success").and_then(Value::as_bool) == Some(false) {
        let err = root
            .get("error")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown slither error")
            .to_string();
        return Err(SlitherParseError::CompilationFailed(err));
    }

    let detectors = root
        .get("results")
        .and_then(|r| r.get("detectors"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Ok(detectors.iter().map(parse_detector).collect())
}

fn parse_detector(d: &Value) -> RawSlitherFinding {
    let detector = str_field(d, "check", "unknown");
    let description = str_field(d, "description", "");
    let markdown = str_field(d, "markdown", "");
    let impact = str_field(d, "impact", "Informational");
    let confidence = str_field(d, "confidence", "Low");

    // Title = first line of the description (sans trailing colon), else detector id.
    let title = description
        .lines()
        .next()
        .map(|l| l.trim().trim_end_matches(':').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| detector.clone());

    let elements = d
        .get("elements")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let loc = extract_location(&elements);
    let evidence = extract_evidence(&elements);

    RawSlitherFinding {
        detector,
        check: title,
        impact,
        confidence,
        description,
        markdown,
        file: loc.file,
        contract: loc.contract,
        function: loc.function,
        line_start: loc.line_start,
        line_end: loc.line_end,
        evidence,
    }
}

#[derive(Default)]
struct Loc {
    file: Option<String>,
    contract: Option<String>,
    function: Option<String>,
    line_start: Option<i32>,
    line_end: Option<i32>,
}

/// Best-effort location: prefer the function element, then a contract element,
/// then the first element with a source mapping.
fn extract_location(elements: &[Value]) -> Loc {
    let mut loc = Loc::default();

    let chosen = elements
        .iter()
        .find(|e| elem_type(e) == "function")
        .or_else(|| elements.iter().find(|e| elem_type(e) == "contract"))
        .or_else(|| elements.first());

    let Some(el) = chosen else {
        return loc;
    };

    match elem_type(el) {
        "function" => loc.function = el.get("name").and_then(Value::as_str).map(String::from),
        "contract" => loc.contract = el.get("name").and_then(Value::as_str).map(String::from),
        _ => {}
    }

    if let Some(sm) = el.get("source_mapping") {
        loc.file = sm
            .get("filename_relative")
            .and_then(Value::as_str)
            .or_else(|| sm.get("filename_short").and_then(Value::as_str))
            .map(String::from);

        if let Some(lines) = sm.get("lines").and_then(Value::as_array) {
            let nums: Vec<i64> = lines.iter().filter_map(Value::as_i64).collect();
            loc.line_start = nums.iter().min().map(|n| *n as i32);
            loc.line_end = nums.iter().max().map(|n| *n as i32);
        }
    }

    // Pull the parent contract name when the element didn't supply one.
    if loc.contract.is_none() {
        loc.contract = el
            .get("type_specific_fields")
            .and_then(|f| f.get("parent"))
            .filter(|p| p.get("type").and_then(Value::as_str) == Some("contract"))
            .and_then(|p| p.get("name").and_then(Value::as_str))
            .map(String::from);
    }

    loc
}

fn extract_evidence(elements: &[Value]) -> Vec<String> {
    let mut ev = Vec::new();
    for el in elements {
        if let Some(name) = el.get("name").and_then(Value::as_str) {
            let s = name.trim().to_string();
            if !s.is_empty() && !ev.contains(&s) {
                ev.push(s);
            }
        }
        if ev.len() >= 5 {
            break;
        }
    }
    ev
}

fn elem_type(e: &Value) -> &str {
    e.get("type").and_then(Value::as_str).unwrap_or("")
}

fn str_field(v: &Value, key: &str, default: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
    {
      "success": true,
      "error": null,
      "results": {
        "detectors": [
          {
            "check": "reentrancy-eth",
            "impact": "High",
            "confidence": "Medium",
            "description": "Reentrancy in Vault.withdraw() (Contract.sol#42-50):\n\tExternal calls:",
            "markdown": "Reentrancy in `Vault.withdraw()`",
            "elements": [
              {
                "type": "function",
                "name": "withdraw",
                "source_mapping": { "filename_relative": "Contract.sol", "lines": [42, 43, 44, 50] },
                "type_specific_fields": { "parent": { "type": "contract", "name": "Vault" } }
              }
            ]
          }
        ]
      }
    }
    "#;

    #[test]
    fn parses_a_detector_into_raw_finding() {
        let out = parse(SAMPLE).expect("parse ok");
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.detector, "reentrancy-eth");
        assert_eq!(f.impact, "High");
        assert_eq!(f.confidence, "Medium");
        assert_eq!(f.function.as_deref(), Some("withdraw"));
        assert_eq!(f.contract.as_deref(), Some("Vault"));
        assert_eq!(f.file.as_deref(), Some("Contract.sol"));
        assert_eq!(f.line_start, Some(42));
        assert_eq!(f.line_end, Some(50));
        assert!(f.check.starts_with("Reentrancy in Vault.withdraw()"));
        assert_eq!(f.evidence, vec!["withdraw".to_string()]);
    }

    #[test]
    fn compilation_failure_is_an_error() {
        let json = r#"{ "success": false, "error": "Invalid solc version", "results": {} }"#;
        match parse(json) {
            Err(SlitherParseError::CompilationFailed(msg)) => assert!(msg.contains("solc")),
            other => panic!("expected CompilationFailed, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(matches!(
            parse("not json"),
            Err(SlitherParseError::MalformedJson(_))
        ));
    }

    #[test]
    fn no_detectors_yields_empty() {
        let json = r#"{ "success": true, "results": { "detectors": [] } }"#;
        assert!(parse(json).unwrap().is_empty());
    }

    /// Parses real `slither --json` output captured from the sandbox image
    /// (Slither 0.11.5) running on a reentrant Vault contract.
    #[test]
    fn parses_real_slither_output() {
        let json = include_str!("testdata/slither_reentrancy.json");
        let out = parse(json).expect("real output parses");
        assert!(!out.is_empty());

        let reentrancy = out
            .iter()
            .find(|f| f.detector == "reentrancy-eth")
            .expect("reentrancy-eth present in real output");
        assert_eq!(reentrancy.impact, "High");
        assert_eq!(reentrancy.confidence, "Medium");
        assert_eq!(reentrancy.contract.as_deref(), Some("Vault"));
        assert_eq!(reentrancy.function.as_deref(), Some("withdraw"));
        assert!(reentrancy.line_start.is_some());
    }
}
