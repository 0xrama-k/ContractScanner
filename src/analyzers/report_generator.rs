//! Report generation (Sections 8, 13): builds the UI/JSON report and the
//! Markdown export from an analysis outcome. Uses normalized findings only.

use serde_json::{json, Value};
use uuid::Uuid;

use crate::analyzers::llm_analyzer::RiskArea;
use crate::analyzers::pipeline::AnalysisOutcome;
use crate::models::finding::{Finding, Severity};

pub struct GeneratedReport {
    pub json_report: Value,
    pub markdown_report: String,
}

struct Counts {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    informational: usize,
}

fn count(findings: &[Finding]) -> Counts {
    let mut c = Counts {
        total: findings.len(),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
    };
    for f in findings {
        match f.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Informational => c.informational += 1,
        }
    }
    c
}

pub fn generate(
    scan_id: Uuid,
    outcome: &AnalysisOutcome,
    contract_summary: &str,
    main_risk_areas: &[RiskArea],
    warnings: &[String],
) -> GeneratedReport {
    let c = count(&outcome.findings);
    let overall = outcome.overall_risk.as_str();

    let json_report = json!({
        "scan_id": scan_id.to_string(),
        "status": "report_ready",
        "summary": {
            "overall_risk": overall,
            "total_findings": c.total,
            "critical": c.critical,
            "high": c.high,
            "medium": c.medium,
            "low": c.low,
            "informational": c.informational,
        },
        "contract_summary": contract_summary,
        "contract_metadata": serde_json::to_value(&outcome.metadata).unwrap_or(Value::Null),
        "main_risk_areas": serde_json::to_value(main_risk_areas).unwrap_or(Value::Array(vec![])),
        "findings": serde_json::to_value(&outcome.findings).unwrap_or(Value::Array(vec![])),
        "warnings": warnings,
    });

    let markdown_report =
        markdown(scan_id, outcome, &c, overall, contract_summary, main_risk_areas, warnings);

    GeneratedReport {
        json_report,
        markdown_report,
    }
}

#[allow(clippy::too_many_arguments)]
fn markdown(
    scan_id: Uuid,
    outcome: &AnalysisOutcome,
    c: &Counts,
    overall: &str,
    contract_summary: &str,
    main_risk_areas: &[RiskArea],
    warnings: &[String],
) -> String {
    let md = &outcome.metadata;
    let mut s = String::new();
    s.push_str("# Smart Contract Security Report\n\n");
    s.push_str("## Summary\n");
    s.push_str(&format!("- Overall risk: {overall}\n"));
    s.push_str(&format!("- Total findings: {}\n", c.total));
    s.push_str(&format!(
        "- Critical: {} · High: {} · Medium: {} · Low: {} · Informational: {}\n",
        c.critical, c.high, c.medium, c.low, c.informational
    ));
    s.push_str(&format!(
        "- File: {}  ·  Pragma: {}  ·  Scan: {}\n\n",
        md.filename,
        md.pragma.as_deref().unwrap_or("_unknown_"),
        scan_id
    ));

    if !contract_summary.trim().is_empty() {
        s.push_str("## What This Contract Does\n");
        s.push_str(&format!("{contract_summary}\n\n"));
    }

    if !main_risk_areas.is_empty() {
        s.push_str("## Main Risk Areas\n");
        for area in main_risk_areas {
            s.push_str(&format!(
                "- {} (based on {})\n",
                area.area,
                if area.based_on_finding_ids.is_empty() {
                    "—".to_string()
                } else {
                    area.based_on_finding_ids.join(", ")
                }
            ));
        }
        s.push('\n');
    }

    s.push_str("## Contract Metadata\n");
    s.push_str(&format!("- Contracts: {}\n", join_or_none(&md.contracts)));
    s.push_str(&format!("- Functions: {}\n", join_or_none(&md.functions)));
    s.push_str(&format!("- Imports: {}\n", join_or_none(&md.imports)));
    s.push_str(&format!(
        "- Unresolved imports: {}\n\n",
        join_or_none(&md.unresolved_imports)
    ));

    s.push_str("## Findings\n\n");
    if outcome.findings.is_empty() {
        s.push_str("_No findings detected by Slither._\n\n");
    }
    for f in &outcome.findings {
        let sev = f.severity.as_str();
        let loc = format!(
            "{}.{} (lines {}–{})",
            f.location.contract.as_deref().unwrap_or("?"),
            f.location.function.as_deref().unwrap_or("?"),
            opt(f.location.line_start),
            opt(f.location.line_end),
        );
        s.push_str(&format!("### [{}] {} — {}\n", sev, f.id, f.title));
        s.push_str(&format!("- Category: {}\n", f.category));
        s.push_str(&format!(
            "- Severity: {}  ·  Confidence: {}  ·  Status: {}\n",
            sev,
            f.confidence.as_str(),
            f.status
        ));
        s.push_str("- Source: Detected by Slither\n");
        s.push_str(&format!("- Location: {loc}\n\n"));

        s.push_str("**Summary**\n");
        s.push_str(&format!("{}\n\n", placeholder(&f.summary)));
        s.push_str("**Technical details**\n");
        s.push_str(&format!("{}\n\n", placeholder(&f.technical_details)));
        s.push_str("**Exploit scenario**\n");
        s.push_str(&format!("{}\n\n", placeholder(&f.exploit_scenario)));
        s.push_str("**Fix suggestion**\n");
        s.push_str(&format!("{}\n\n", placeholder(&f.fix_suggestion)));
        if !f.false_positive_note.trim().is_empty() {
            s.push_str("**False-positive note**\n");
            s.push_str(&format!("{}\n\n", f.false_positive_note));
        }
        if !f.evidence.is_empty() {
            s.push_str("**Evidence**\n```solidity\n");
            s.push_str(&f.evidence.join("\n"));
            s.push_str("\n```\n\n");
        }
        if let Some(score) = &f.score {
            s.push_str(&format!(
                "**Score breakdown**\n- base {} / confidence {} / exploitability {} / asset {} / final {:.2}\n\n",
                score.base_severity, score.confidence, score.exploitability, score.asset_impact, score.final_score
            ));
        }
        s.push_str("---\n\n");
    }

    s.push_str("## Notes\n");
    s.push_str("- This report is based on Slither static analysis. Detected findings are not guaranteed vulnerabilities; review confidence and false-positive notes.\n");
    for w in warnings {
        s.push_str(&format!("- {w}\n"));
    }
    s
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "_none_".to_string()
    } else {
        items.join(", ")
    }
}

fn opt(v: Option<i32>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "?".to_string())
}

fn placeholder(s: &str) -> String {
    if s.trim().is_empty() {
        "_Not available._".to_string()
    } else {
        s.to_string()
    }
}
