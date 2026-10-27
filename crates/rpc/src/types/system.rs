//! JSON shapes of node status, programs, proving, validators and runtime calls.

use neutrin0_primitives::{Hash, Validator};
use serde::{Deserialize, Serialize};

use super::{BytesHex, HashHex, Wei};

/// JSON shape returned by `system_health`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthJson {
    /// Number of currently connected libp2p peers.
    pub peers: u64,
    /// `true` while the sync driver has not reached the live-following state.
    pub is_syncing: bool,
    /// `true` if a WASM runtime is attached and queries are usable.
    pub runtime_available: bool,
    /// Local mempool transaction count.
    pub mempool: u64,
    /// Head block height.
    pub head_height: u64,
}

/// JSON shape returned by `system_info`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoJson {
    /// Content hash of the attached WASM runtime, if any.
    pub runtime_code_hash: Option<HashHex>,
}

/// One installed Guest, as returned by `programs_status`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstalledGuestJson {
    /// Verifying-key digest.
    pub digest: [u32; 8],
    /// BLAKE3 hash of the ELF bytes.
    pub elf_hash: HashHex,
}

/// Progress of one artifact, as returned by `programs_status`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactProgressJson {
    /// Content hash.
    pub content_hash: HashHex,
    /// Bytes received or sent so far.
    pub bytes: u32,
    /// Complete length.
    pub total: u32,
}

/// One persisted artifact, as returned by `programs_status`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedArtifactJson {
    /// Content hash.
    pub content_hash: HashHex,
    /// `wasm`, `elf` or `unknown`.
    pub kind: String,
}

/// JSON shape returned by `programs_status` (design 20, on-chain program distribution).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramsStatusJson {
    /// Guests the proof backend can prove under.
    pub installed_guests: Vec<InstalledGuestJson>,
    /// Runtime code hashes the executor can run.
    pub runtimes: Vec<HashHex>,
    /// Content hashes governance currently names.
    pub wanted: Vec<HashHex>,
    /// Artifacts being reassembled from the program lane.
    pub assembling: Vec<ArtifactProgressJson>,
    /// Complete artifacts not installed, usually because governance has not
    /// named them.
    pub complete: Vec<HashHex>,
    /// Artifacts persisted on disk.
    pub persisted: Vec<PersistedArtifactJson>,
    /// Local file being streamed into produced blocks.
    pub publishing: Option<ArtifactProgressJson>,
    /// Files waiting in the publish directory; their names are on the
    /// management socket.
    pub queued_publications: u64,
    /// Programs of the enacted, not yet activated switch that this node has
    /// not installed (`runtime`, `fact`, `evidence`, `block`); empty once it
    /// is ready, absent when no switch is scheduled.
    pub scheduled_missing: Option<Vec<String>>,
}

/// JSON shape returned by `proving_status` (design 08): what this node proves
/// and which account its receipts and chunk proofs name.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvingStatusJson {
    /// Whether a proof backend with an embedded Block program is installed.
    pub backend_ready: bool,
    /// Account named in this node's receipts and chunk proofs: the configured
    /// prover address, else the local validator's withdrawal account.
    pub prover_address: Option<HashHex>,
    /// Whether the node proves candidates it did not produce.
    pub prove_foreign_blocks: bool,
    /// Retained candidates this node would prove now, counted up to 64.
    pub pending_block_proofs: u64,
    /// Chunk whose proof this node is computing, if any.
    pub running_chunk_proof: Option<u64>,
    /// Height of the highest block whose ancestors are all proven.
    pub proven_head_height: u64,
    /// Height of the candidate chain this node follows.
    pub pending_head_height: u64,
}

/// JSON shape returned by `validator_set_active`. Validators are
/// emitted in the order the engine uses for proposer eligibility.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidatorJson {
    /// BLS public key in hex.
    pub pubkey: BytesHex,
    /// Withdrawal credentials hash.
    pub withdrawal_credentials: HashHex,
    /// Effective stake (consensus weight), in wei.
    pub effective_stake: Wei,
    /// Activation epoch.
    pub activation_epoch: u64,
    /// Exit epoch (`u64::MAX` if not exiting).
    pub exit_epoch: u64,
}

impl From<&Validator> for ValidatorJson {
    fn from(v: &Validator) -> Self {
        Self {
            pubkey: BytesHex(v.pubkey.to_vec()),
            withdrawal_credentials: HashHex(v.withdrawal_credentials),
            effective_stake: Wei(v.effective_stake),
            activation_epoch: v.activation_epoch,
            exit_epoch: v.exit_epoch,
        }
    }
}

/// JSON shape returned by `runtime_call`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCallResultJson {
    /// Runtime-defined status code.
    pub code: u32,
    /// Runtime-defined response payload, hex-encoded.
    pub payload: BytesHex,
    /// Gas the query consumed.
    pub gas_used: u64,
}

/// JSON shape returned by `mempool_submit`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SubmitResultJson {
    /// BLAKE3 hash of the submitted transaction bytes.
    pub hash: HashHex,
}

impl SubmitResultJson {
    /// Wrap a raw `Hash` into the JSON envelope.
    #[must_use]
    pub const fn new(hash: Hash) -> Self {
        Self {
            hash: HashHex(hash),
        }
    }
}
