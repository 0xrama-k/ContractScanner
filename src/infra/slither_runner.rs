//! Slither runner: ties the temp workspace, Docker sandbox, and JSON adapter
//! together into a single `analyze` call returning raw findings.

// Consumed by the scan service when the pipeline is wired into the lifecycle.
#![allow(dead_code)]

use uuid::Uuid;

use crate::analyzers::slither_adapter::{self, SlitherParseError};
use crate::infra::docker_runner::{DockerLimits, DockerRunner};
use crate::infra::temp_files::TempScanDir;
use crate::models::raw_finding::RawSlitherFinding;

#[derive(Debug, thiserror::Error)]
pub enum SlitherError {
    #[error("scan workspace error: {0}")]
    Workspace(String),
    #[error("docker error: {0}")]
    Docker(String),
    #[error("slither timed out")]
    Timeout,
    #[error("slither produced no usable output")]
    NoOutput,
    #[error("slither could not compile the contract: {0}")]
    Compilation(String),
    #[error("could not parse slither output: {0}")]
    Parse(String),
}

pub struct SlitherRunner {
    docker: DockerRunner,
    limits: DockerLimits,
}

impl SlitherRunner {
    pub fn new(docker: DockerRunner, limits: DockerLimits) -> Self {
        Self { docker, limits }
    }

    /// Run Slither on `source` in an isolated sandbox and return raw findings.
    /// The temp workspace is always cleaned up (via `TempScanDir`'s Drop).
    pub async fn analyze(
        &self,
        scan_id: Uuid,
        source: &str,
    ) -> Result<Vec<RawSlitherFinding>, SlitherError> {
        let dir = TempScanDir::create(scan_id).map_err(|e| SlitherError::Workspace(e.to_string()))?;
        dir.write_source(source)
            .map_err(|e| SlitherError::Workspace(e.to_string()))?;

        let outcome = self
            .docker
            .run_slither(dir.path(), &self.limits)
            .await
            .map_err(|e| SlitherError::Docker(e.to_string()))?;

        if outcome.timed_out {
            return Err(SlitherError::Timeout);
        }
        tracing::debug!(
            exit_code = ?outcome.exit_code,
            "slither sandbox finished"
        );

        // Slither's exit code is unreliable (255 when findings exist), so success
        // is judged by the presence + `success` flag of the JSON output.
        let json = dir
            .read_output()
            .map_err(|e| SlitherError::Workspace(e.to_string()))?
            .ok_or_else(|| {
                tracing::warn!(stderr = %outcome.stderr, "slither produced no output file");
                SlitherError::NoOutput
            })?;

        match slither_adapter::parse(&json) {
            Ok(raws) => Ok(raws),
            Err(SlitherParseError::CompilationFailed(m)) => Err(SlitherError::Compilation(m)),
            Err(SlitherParseError::MalformedJson(m)) => Err(SlitherError::Parse(m)),
        }
    }
}
