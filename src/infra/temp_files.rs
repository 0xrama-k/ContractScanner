//! Temporary per-scan workspace (Section 15).
//!
//! `TempScanDir` owns a `<temp>/contract-scanner/scans/<scan_id>/` folder. Its
//! `Drop` impl removes the folder, so cleanup runs even on error/panic paths
//! (the blueprint's "trigger even on scan failure" requirement). A separate
//! reaper still sweeps orphans left by hard crashes.

use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

pub struct TempScanDir {
    path: PathBuf,
}

impl TempScanDir {
    /// Base directory for all scan workspaces.
    pub fn base_dir() -> PathBuf {
        std::env::temp_dir().join("contract-scanner").join("scans")
    }

    pub fn create(scan_id: Uuid) -> std::io::Result<Self> {
        let path = Self::base_dir().join(scan_id.to_string());
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the submitted source as `Contract.sol`.
    pub fn write_source(&self, source: &str) -> std::io::Result<()> {
        fs::write(self.path.join("Contract.sol"), source)
    }

    /// Read `slither-output.json` if Slither produced it.
    pub fn read_output(&self) -> std::io::Result<Option<String>> {
        let p = self.path.join("slither-output.json");
        if p.exists() {
            Ok(Some(fs::read_to_string(p)?))
        } else {
            Ok(None)
        }
    }
}

impl Drop for TempScanDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
