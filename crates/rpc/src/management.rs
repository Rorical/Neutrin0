//! Separate local management protocol. No methods are registered on public RPC.

use serde::{Deserialize, Serialize};

use crate::{BytesHex, HashHex};

/// A single local management operation. There is no arbitrary signing endpoint.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ManagementRequest {
    /// Inspect local policy and prerequisites.
    Status,
    /// Stop every new consensus signature and block production.
    PauseSigning,
    /// Permit signing subject to existing safety and bootstrap checks.
    ResumeSigning,
    /// Stop producing blocks while continuing consensus voting.
    PauseProduction,
    /// Permit production subject to signing policy and eligibility.
    ResumeProduction,
    /// Close the local signer and request the normal bounded node shutdown.
    Shutdown,
    /// Write the latest finalized endpoint to a new snapshot file another
    /// node can bootstrap from without peers.
    ExportSnapshot {
        /// Absolute path of the file to create; an existing file is refused.
        path: String,
        /// Chunk count of the importer's trust boundary to open under the
        /// endpoint, when it is neither the specification's start nor the
        /// endpoint itself.
        anchor_chunks: Option<u64>,
    },
}

/// What a snapshot export wrote.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotReport {
    /// Checkpoint hash of the exported endpoint.
    pub endpoint: HashHex,
    /// Finalized chunks the endpoint covers.
    pub chunks: u64,
    /// Objects written, programs included.
    pub objects: u64,
    /// Programs the manifest names that the node does not hold, left out;
    /// an importer must hold them already.
    pub programs_left_out: u64,
    /// File size in bytes.
    pub bytes: u64,
}

/// An acknowledged policy together with the locally authenticated node identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent operator and safety gates are reported separately."
)]
pub struct ManagementStatus {
    /// Chain identifier.
    pub chain_id: u64,
    /// Full chain-spec identity.
    pub chain_spec_hash: HashHex,
    /// Configured public BLS identity; secret material never travels here.
    pub validator_public_key: Option<BytesHex>,
    /// Current committee index resolved by identity, never the configured
    /// genesis index.
    pub validator_index: Option<u32>,
    /// `no_key`, `unavailable`, `not_in_committee`, `zero_stake` or `member`.
    /// Membership does not imply slot eligibility or that signing can proceed.
    pub membership: String,
    /// This node's libp2p peer ID, for other nodes' bootnode addresses.
    pub local_peer_id: Option<String>,
    /// This node's own votes in each live BFT session.
    pub local_votes: Vec<LocalVotesJson>,
    /// Files waiting in the program publish directory.
    pub publish_queue: Vec<String>,
    /// Operator signing policy, effective in this process.
    pub signing_paused: bool,
    /// Operator production policy, independent of signing pause.
    pub production_paused: bool,
    /// A failed policy write closed both gates; persistence must be repaired.
    pub persistence_fault: bool,
    /// This engine cannot resume signing because shutdown started.
    pub stopping: bool,
    /// Bootstrap still forbids validator work.
    pub bootstrap_pending: bool,
    /// Whether the configured identity is active in the current authenticated set.
    pub validator_active: bool,
    /// First slot the node signs in after its doppelganger quiet period.
    pub signing_quiet_until_slot: u64,
    /// A message signed by the local key that this node did not sign, which
    /// paused signing and production until the operator resumes them.
    pub doppelganger: Option<String>,
    /// Current local head height.
    pub head_height: u64,
}

/// Whether this node voted in one live BFT round.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVotesJson {
    /// Chunk under vote.
    pub chunk_id: u64,
    /// Current round.
    pub round: u32,
    /// This node prevoted.
    pub prevoted: bool,
    /// This node precommitted.
    pub precommitted: bool,
}

/// One response per connection, including structured command failures.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementResponse {
    /// A completed read or durable policy change.
    Ok {
        /// Effective state at the acknowledgment barrier.
        status: ManagementStatus,
    },
    /// A completed snapshot export.
    Exported {
        /// What the file holds.
        snapshot: SnapshotReport,
    },
    /// A refused request or failed durable policy change.
    Error {
        /// Human-readable reason, without secret material.
        message: String,
    },
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{management_call, read_frame, validate_directory, validate_peer, write_frame};
