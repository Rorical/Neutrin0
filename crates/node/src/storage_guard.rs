//! Unconditional free-space quota for the data directory.
//!
//! Raw history prunes only behind finality, so while chunk proofs stall the
//! node keeps storing unfinalized candidates with their witnesses and diffs.
//! Below `min_free_bytes` the guard raises storage pressure: the producer
//! stops and peer candidates are ignored, while receipts, votes and complete
//! chunk sync continue so finality, and the pruning it triggers, can release
//! space. Below `halt_free_bytes` the guard fails, which stops the node before
//! the database fills the filesystem and degrades to failing writes.

use crate::config::StorageConfig;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use sysinfo::Disks;
use tracing::{info, warn};

/// Interval between free-space samples.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

/// Sample the data filesystem until it falls below the halt floor.
///
/// # Errors
/// Returns the halt reason, which stops the node through task supervision.
#[expect(
    clippy::redundant_pub_crate,
    reason = "the guard is a runner task inside this crate"
)]
pub(crate) async fn run(
    path: PathBuf,
    config: StorageConfig,
    pressure: Arc<AtomicBool>,
) -> Result<(), String> {
    let path = path.canonicalize().unwrap_or(path);
    let mut unknown_reported = false;
    loop {
        let sample_path = path.clone();
        // Mount enumeration is a blocking system call.
        let sampled = tokio::task::spawn_blocking(move || {
            crate::process_metrics::data_filesystem(&mut Disks::new(), &sample_path)
                .map(|(_, available)| available)
        })
        .await
        .map_err(|error| format!("storage sampler failed: {error}"))?;
        match sampled {
            Some(available) => {
                unknown_reported = false;
                if available < config.halt_free_bytes {
                    return Err(format!(
                        "data filesystem has {available} free bytes, below storage.halt_free_bytes = {}; \
                         stopping before the database fills it",
                        config.halt_free_bytes
                    ));
                }
                let next = next_pressure(pressure.load(Ordering::Relaxed), available, &config);
                if pressure.swap(next, Ordering::Relaxed) != next {
                    if next {
                        warn!(
                            available,
                            min_free_bytes = config.min_free_bytes,
                            "storage pressure: production and new candidate imports paused"
                        );
                    } else {
                        info!(available, "storage pressure cleared");
                    }
                }
            }
            None if !unknown_reported => {
                unknown_reported = true;
                warn!(path = %path.display(), "data filesystem free space unavailable; storage quota inactive");
            }
            None => {}
        }
        tokio::time::sleep(SAMPLE_INTERVAL).await;
    }
}

/// Pressure starts below `min_free_bytes` and clears only a tenth above it,
/// so pruning that frees a little space does not toggle production per sample.
const fn next_pressure(current: bool, available: u64, config: &StorageConfig) -> bool {
    if current {
        available
            < config
                .min_free_bytes
                .saturating_add(config.min_free_bytes / 10)
    } else {
        available < config.min_free_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_clears_only_above_its_hysteresis_band() {
        let config = StorageConfig {
            min_free_bytes: 1000,
            halt_free_bytes: 100,
        };
        assert!(!next_pressure(false, 1000, &config));
        assert!(next_pressure(false, 999, &config));
        assert!(next_pressure(true, 1099, &config));
        assert!(!next_pressure(true, 1100, &config));
    }
}
