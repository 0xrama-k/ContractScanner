//! Orphan reaper (Section 15). Periodically removes leftover temp scan folders
//! that outlived their scan (e.g. a crash before `TempScanDir`'s Drop ran).
//!
//! Deliberately simple: filesystem age only. Containers run with `--rm` so they
//! self-remove on exit; a durable queue/worker is a Future item.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::infra::temp_files::TempScanDir;

/// Spawn the periodic reaper. `threshold` should comfortably exceed the longest
/// possible scan so active workspaces are never reaped mid-run.
pub fn spawn(threshold: Duration, interval: Duration) {
    let base = TempScanDir::base_dir();
    tokio::spawn(async move {
        loop {
            let removed = reap_once(&base, threshold);
            if removed > 0 {
                tracing::info!(removed, "reaper removed orphan scan folders");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// Remove scan subdirectories older than `threshold`. Returns how many were removed.
fn reap_once(base: &Path, threshold: Duration) -> usize {
    let now = SystemTime::now();
    let mut removed = 0;

    let Ok(entries) = fs::read_dir(base) else {
        return 0; // base may not exist yet — nothing to do
    };

    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let aged_out = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .map(|age| age > threshold)
            .unwrap_or(false);

        if aged_out && fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }

    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn removes_aged_dirs_only() {
        let base = std::env::temp_dir().join(format!("reaper-test-{}", Uuid::new_v4()));
        let old = base.join("old-scan");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("Contract.sol"), "x").unwrap();

        // threshold 0 => anything older than "now" is reaped.
        std::thread::sleep(Duration::from_millis(20));
        let removed = reap_once(&base, Duration::ZERO);
        assert_eq!(removed, 1);
        assert!(!old.exists());

        // A fresh dir with a large threshold survives.
        let fresh = base.join("fresh-scan");
        fs::create_dir_all(&fresh).unwrap();
        let removed = reap_once(&base, Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert!(fresh.exists());

        let _ = fs::remove_dir_all(&base);
    }
}
