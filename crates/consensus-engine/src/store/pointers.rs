//! Stable pointer / metadata key names used in the `Finalized` and
//! `Meta` columns.

/// Latest produced block hash (heaviest tip of the local view).
pub const TIP: &[u8] = b"tip";

/// Latest finalized block hash.
pub const FINALIZED_HEAD: &[u8] = b"finalized_head";

/// Highest finalized chunk id (none until chunk 0 finalizes).
pub const LATEST_FINALIZED_CHUNK_ID: &[u8] = b"latest_chunk_id";

/// Current VRF seed folded over the latest finalized chunk.
///
/// Persisted so restarts after one or more chunks have closed resume
/// against the same VRF eligibility surface they were producing under;
/// without it [`Engine::open`](crate::Engine::open) would re-derive the genesis seed and
/// silently fork.
pub const FINALIZED_SEED: &[u8] = b"finalized_seed";

/// Index of the currently active validator-set snapshot.
///
/// Persisted so restarts resume with the correct active validator list
/// for proposer eligibility and BFT quorum weighting.
pub const LATEST_VALIDATOR_SET_INDEX: &[u8] = b"latest_vs_idx";

/// BLAKE3 hash of the borsh-encoded chain spec.
pub const CHAIN_SPEC_HASH: &[u8] = b"chain_spec_hash";

/// Chain spec hash of signing protection imported before genesis
/// initialization, which genesis checks and consumes.
pub const SIGNING_TRANSFER_SPEC: &[u8] = b"signing_transfer_spec";

/// Trusted history proof profile, persisted independently of peer proof envelopes.
pub const HISTORY_PROOF_DOMAIN: &[u8] = b"history_proof_domain";

/// Authenticated consensus boundary and the full next execution context.
pub const CONSENSUS_STATE: &[u8] = b"full_consensus_state";

/// Authenticated manifest and trust origin of an unfinished snapshot bootstrap.
pub const BOOTSTRAP_PENDING: &[u8] = b"bootstrap_pending";
/// Prefix of every state-download row: per-root summaries follow it with
/// `/`, staged rows with [`STATE_DOWNLOAD_ENTRY_PREFIX`].
pub const STATE_DOWNLOAD: &[u8] = b"state_download";
/// Prefix for per-root progress and the objects staged for every root.
pub const STATE_DOWNLOAD_ENTRY_PREFIX: &[u8] = b"state_download_entry/";
