//! Analysis pipeline: preprocess -> Slither -> normalize -> score (Sections 3-8).
//! Produces the data the report generator and persistence layer consume.

#![allow(dead_code)]

use uuid::Uuid;

use crate::analyzers::risk_scorer::{self, OverallRisk, ScoreInput};
use crate::analyzers::{finding_normalizer, solidity_preprocessor};
use crate::infra::slither_runner::{SlitherError, SlitherRunner};
use crate::models::finding::Finding;
use crate::models::metadata::ContractMetadata;

pub struct AnalysisOutcome {
    pub metadata: ContractMetadata,
    pub findings: Vec<Finding>,
    pub overall_risk: OverallRisk,
}

/// Run the full analysis for one source file.
pub async fn analyze(
    runner: &SlitherRunner,
    scan_id: Uuid,
    filename: &str,
    source: &str,
) -> Result<AnalysisOutcome, SlitherError> {
    // 1. Lightweight metadata (full source; never blocked by size).
    let metadata = solidity_preprocessor::extract(filename, source);

    // 2. Slither in the sandbox -> raw findings.
    let raws = runner.analyze(scan_id, source).await?;

    // 3. Normalize + dedup.
    let mut findings = finding_normalizer::normalize(raws);

    // 4. Score each finding; the final (possibly escalated) severity is what we show.
    for f in &mut findings {
        let breakdown = risk_scorer::score(&ScoreInput {
            detector: &f.detector,
            severity: f.severity,
            confidence: f.confidence,
        });
        f.severity = breakdown.final_severity;
        f.score = Some(breakdown);
    }

    let severities: Vec<_> = findings.iter().map(|f| f.severity).collect();
    let overall_risk = risk_scorer::overall_risk(&severities);

    Ok(AnalysisOutcome {
        metadata,
        findings,
        overall_risk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::docker_runner::{DockerLimits, DockerRunner};

    const VULNERABLE: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
        balances[msg.sender] = 0;
    }
}
"#;

    // Real end-to-end run through Docker + Slither. Ignored by default (needs the
    // sandbox image). Run with:
    //   $env:DOCKER_BIN="...\docker.exe"; cargo test -- --ignored
    #[tokio::test]
    #[ignore = "requires Docker and the contract-scanner-slither image"]
    async fn end_to_end_detects_reentrancy() {
        let docker_bin = std::env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string());
        let image = std::env::var("SLITHER_IMAGE")
            .unwrap_or_else(|_| "contract-scanner-slither:latest".to_string());

        let runner = SlitherRunner::new(DockerRunner::new(docker_bin, image), DockerLimits::default());
        let out = analyze(&runner, Uuid::new_v4(), "Contract.sol", VULNERABLE)
            .await
            .expect("analysis succeeds");

        assert_eq!(out.metadata.contracts, vec!["Vault".to_string()]);
        let reentrancy = out
            .findings
            .iter()
            .find(|f| f.detector == "reentrancy-eth")
            .expect("reentrancy finding present");
        assert!(reentrancy.score.is_some());
        assert_eq!(reentrancy.category, "Reentrancy");
        // reentrancy-eth + High confidence escalates to Critical; here confidence
        // is Medium, so it should land High (not escalated).
        println!(
            "reentrancy severity={:?} score={:?} overall={:?}",
            reentrancy.severity, reentrancy.score, out.overall_risk
        );
    }
}
