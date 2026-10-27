//! Local trust anchors: the light client's checkpoint policy and the
//! full-node bootstrap section.

#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use std::path::Path;

use serde::Deserialize;

/// Local weak-subjectivity trust configuration. Peers cannot supply this anchor.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LightClientConfig {
    /// Local file containing a Borsh-encoded trusted `Checkpoint`.
    /// When omitted, the chain specification's genesis is the anchor.
    pub trusted_checkpoint_path: Option<std::path::PathBuf>,
    /// Unix time at which the explicit checkpoint was independently trusted.
    /// Must accompany `trusted_checkpoint_path`; genesis uses `genesis_time`.
    /// Weak subjectivity runs from this or the checkpoint block's slot time,
    /// whichever is earlier.
    pub trusted_at: Option<u64>,
    /// Maximum tolerated future endpoint timestamp, in seconds.
    pub max_future_drift_secs: u64,
    /// Distinct peers whose latest advertised endpoint is sampled.
    pub sample_peers: usize,
    /// Sampled peers that must advertise an endpoint identically before the
    /// client fetches and accepts its History proof.
    pub sample_quorum: usize,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        let sampling = neutrin0_light_client::sampling::SamplingPolicy::DEFAULT;
        Self {
            trusted_checkpoint_path: None,
            trusted_at: None,
            max_future_drift_secs: 30,
            sample_peers: sampling.peers,
            sample_quorum: sampling.quorum,
        }
    }
}

impl LightClientConfig {
    /// The peer sampling policy this configuration selects.
    #[must_use]
    pub const fn sampling(&self) -> neutrin0_light_client::sampling::SamplingPolicy {
        neutrin0_light_client::sampling::SamplingPolicy {
            peers: self.sample_peers,
            quorum: self.sample_quorum,
        }
    }

    /// Reject a sampling policy outside `1 <= sample_quorum <= sample_peers <= 64`.
    ///
    /// # Errors
    /// Returns the operator-facing reason.
    pub fn validate(&self) -> Result<(), String> {
        if !self.sampling().is_valid() {
            return Err(format!(
                "light_client requires 1 <= sample_quorum <= sample_peers <= {}",
                neutrin0_light_client::sampling::MAX_SAMPLE_PEERS
            ));
        }
        Ok(())
    }
}

/// Largest accepted trusted checkpoint file; a Borsh `Checkpoint` is far smaller.
pub(crate) const MAX_TRUSTED_CHECKPOINT_BYTES: u64 = 1024;

/// Read a locally configured trusted checkpoint file, buffering at most one
/// byte beyond [`MAX_TRUSTED_CHECKPOINT_BYTES`], so a misconfigured large or
/// unbounded file (such as `/dev/zero`) is refused without reading it into
/// memory. Returns `Ok(None)` when the file exceeds the limit.
///
/// # Errors
/// Returns the I/O error of opening or reading the file.
pub(crate) fn read_trusted_checkpoint(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_TRUSTED_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let within_limit =
        u64::try_from(bytes.len()).is_ok_and(|len| len <= MAX_TRUSTED_CHECKPOINT_BYTES);
    Ok(within_limit.then_some(bytes))
}

/// Full-node state bootstrap. Archive nodes replay complete source history,
/// from a hard fork's start under its successor.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapConfig {
    /// Enable proof-backed state bootstrap when the local finalized anchor is behind.
    pub enabled: bool,
    /// Optional independently trusted checkpoint file, never selected by peers.
    pub trusted_checkpoint_path: Option<std::path::PathBuf>,
    /// Original local trust time, required with the checkpoint file; weak
    /// subjectivity runs from this or the checkpoint block's slot time,
    /// whichever is earlier.
    pub trusted_at: Option<u64>,
    /// Maximum accepted future endpoint timestamp.
    pub max_future_drift_secs: u64,
    /// Snapshot file (`neutrin0-cli node export-snapshot`) to bootstrap from
    /// at startup instead of peers. It authenticates against the same trust
    /// boundary and is not judged stale; an endpoint local finality already
    /// reached is skipped. Under a hard fork's successor, the predecessor's
    /// endpoint snapshot starts the successor, for archives too.
    pub snapshot_path: Option<std::path::PathBuf>,
    /// Data directory of the predecessor this node succeeds at a hard fork
    /// (design 20). Its endpoint bundle gives this node's specification,
    /// completed with this binary's programs and written to
    /// `<data_dir>/chain-spec.toml`, its start, its signing protection and
    /// the predecessor's carried retention. `chain_spec_path` and
    /// `snapshot_path` stay unset.
    pub fork_from: Option<std::path::PathBuf>,
}
impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_checkpoint_path: None,
            trusted_at: None,
            max_future_drift_secs: 30,
            snapshot_path: None,
            fork_from: None,
        }
    }
}
