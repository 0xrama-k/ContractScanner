//! Docker sandbox runner (Section 15). Runs the Slither image with the network
//! disabled and CPU/RAM/PID limits, under a wall-clock timeout.

// Consumed by the scan service when the pipeline is wired into the lifecycle.
#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use tokio::process::Command;

/// Resource limits applied to each sandbox run.
#[derive(Debug, Clone)]
pub struct DockerLimits {
    pub memory: String,
    pub cpus: String,
    pub pids: u32,
    pub timeout: Duration,
}

impl Default for DockerLimits {
    fn default() -> Self {
        Self {
            memory: "1g".to_string(),
            cpus: "1".to_string(),
            pids: 256,
            timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
pub struct DockerOutcome {
    /// Process exit code. NOTE: Slither exits 255 when it finds issues, so a
    /// non-zero code is NOT a failure — the caller checks the JSON output file.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stderr: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error("failed to run docker: {0}")]
    Run(String),
}

pub struct DockerRunner {
    docker_bin: String,
    image: String,
}

impl DockerRunner {
    pub fn new(docker_bin: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            docker_bin: docker_bin.into(),
            image: image.into(),
        }
    }

    /// Run Slither on `<host_scan_dir>/Contract.sol`, writing
    /// `<host_scan_dir>/slither-output.json`.
    pub async fn run_slither(
        &self,
        host_scan_dir: &Path,
        limits: &DockerLimits,
    ) -> Result<DockerOutcome, DockerError> {
        let mount = format!("{}:/scan", host_scan_dir.display());

        let mut cmd = Command::new(&self.docker_bin);
        cmd.args([
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            &limits.memory,
            "--cpus",
            &limits.cpus,
            "--pids-limit",
            &limits.pids.to_string(),
            "-v",
            &mount,
            &self.image,
            "sh",
            "-c",
            "slither /scan/Contract.sol --json /scan/slither-output.json",
        ]);
        // Kill the docker client if we time out and drop the future.
        cmd.kill_on_drop(true);

        match tokio::time::timeout(limits.timeout, cmd.output()).await {
            Ok(Ok(output)) => Ok(DockerOutcome {
                exit_code: output.status.code(),
                timed_out: false,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }),
            Ok(Err(e)) => Err(DockerError::Run(e.to_string())),
            Err(_) => Ok(DockerOutcome {
                exit_code: None,
                timed_out: true,
                stderr: "slither run exceeded timeout".to_string(),
            }),
        }
    }
}
