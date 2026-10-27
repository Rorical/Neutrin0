#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]

//! Shared primitive types and chain-spec constants for Neutrin0.
//!
//! This crate is the canonical source of truth for consensus constants that
//! must be shared by the engine, runtime ABI, proof system, and light client.

extern crate alloc;

mod account;
mod arithmetic;
mod bit_vec;
mod boundary;
mod bounded_bytes;
mod constants;
mod domain;
mod hashing;
mod params;
mod programs;
mod spec;
#[cfg(test)]
mod tests;

pub use account::{is_runtime_account, runtime_account};
pub use arithmetic::{
    FIXED_U128_FRAC_BITS, FIXED_U128_ONE, MAX_TOTAL_STAKE, fixed_u128_from_integer, mul_div_floor,
    quorum_fraction_valid, quorum_reached, wide_remainder, widening_mul,
};
pub use bit_vec::BitVec;
pub use boundary::{ChainBinding, ConsensusBoundary, ScheduledFork};
pub use bounded_bytes::{BoundedBytes, BoundsError};
pub use constants::{
    DEFAULT_ABANDONMENT_PENALTY_AMOUNT, DEFAULT_ACTIVATION_DELAY_EPOCHS,
    DEFAULT_ANNUAL_ISSUANCE_BPS, DEFAULT_BFT_ROUND_TIMEOUT_BASE_SECS,
    DEFAULT_BFT_ROUND_TIMEOUT_STEP_SECS, DEFAULT_CHUNK_PROVER_FEE_BPS, DEFAULT_CHUNK_SIZE,
    DEFAULT_EPOCH_LENGTH_IN_CHUNKS, DEFAULT_EXIT_DELAY_EPOCHS,
    DEFAULT_EXPECTED_AGGREGATORS_PER_ROUND, DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
    DEFAULT_INACTIVITY_LEAK_AMOUNT, DEFAULT_LIGHT_CLIENT_STALE_THRESHOLD_SECS,
    DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES, DEFAULT_MAX_RECEIPTS_PER_BLOCK,
    DEFAULT_MIN_VALIDATOR_STAKE, DEFAULT_PROOF_EXCLUSIVE_SLOTS, DEFAULT_PROOF_ORPHAN_SLOTS,
    DEFAULT_SLOT_DURATION_SECS, DEFAULT_UNBONDING_DELAY_BLOCKS, DEFAULT_VOTE_SUBNETS,
    DEFAULT_WEAK_SUBJECTIVITY_PERIOD_SECS, MAX_BLOCK_PROVING_INPUT_BYTES, MAX_CHAIN_NAME_BYTES,
    MAX_CHUNK_RATIFICATIONS, MAX_CONSENSUS_COMMITTEE_BLOCKS, MAX_CONSENSUS_VALIDATORS,
    MAX_GOSSIP_BLOCK_BYTES, MAX_METADATA_BYTES, MAX_PROVEN_BLOCK_BYTES, MAX_STATE_DIFF_BYTES,
    MAX_VOTE_SUBNETS, NATIVE_TOKEN_DECIMALS, SECONDS_PER_YEAR, WEI_PER_TOKEN, committee_size_valid,
    max_committee_size,
};
pub use domain::{ConsensusDomain, MAX_PRIOR_DOMAINS, PriorDomain, PriorDomains};
pub use hashing::{
    Blake3Hasher, EMPTY_HISTORY_ROOT, EMPTY_MERKLE_ROOT, ZERO_HASH, blake3_256,
    da_root_from_lane_roots, merkle_root_from_hashes, merkle_root_of_hashes, transaction_leaf,
    transactions_root, transactions_root_of_blobs, validators_root,
};
pub use params::{ConsensusParams, LightClientParams, ProofParams, RuntimeParams};
pub use programs::{ExecutionPrograms, GenesisArtifacts, PinnedPrograms, ProgramSet};
pub use spec::{ChainSpec, ChainSpecError, ForkAnchor, RuntimeInfo, Validator};

/// A 32-byte cryptographic digest.
pub type Hash = [u8; 32];
/// Chain identifier, encoded little-endian in signed messages.
pub type ChainId = u64;
/// Consensus slot number.
pub type Slot = u64;
/// Staking/reward epoch number.
pub type Epoch = u64;
/// Monotonic block height.
pub type Height = u64;
/// Finality/proof chunk identifier.
pub type ChunkId = u64;
/// Recursive checkpoint index.
pub type CheckpointIndex = u64;
/// Index into the active validator set.
pub type ValidatorIndex = u32;
/// Runtime state trie root.
pub type StateRoot = Hash;
/// Block header hash.
pub type BlockHash = Hash;
/// Chunk commitment hash.
pub type ChunkHash = Hash;
/// Public randomness seed.
pub type Seed = Hash;
/// Fixed-point `Q64.64` value.
pub type FixedU128 = u128;
/// BLS12-381 G1 public key, compressed.
pub type BlsPublicKey = [u8; 48];
/// BLS12-381 G2 signature, compressed.
pub type BlsSignature = [u8; 96];
/// Secp256k1 public key, compressed.
pub type Secp256k1PublicKey = [u8; 33];
/// Secp256k1 recoverable or compact signature bytes.
pub type Secp256k1Signature = [u8; 65];
/// Consensus domain tag. All domain tags are exactly 16 bytes.
pub type DomainTag = [u8; 16];

/// BLS-VRF eval/verify domain.
pub const DOMAIN_VRF: DomainTag = *b"NEUTRIN0_VRF____";
/// Block header proposer-signature domain.
pub const DOMAIN_PROPOSER_SIG: DomainTag = *b"NEUTRIN0_PROPOSE";
/// Finality prevote domain.
pub const DOMAIN_PREVOTE: DomainTag = *b"NEUTRIN0_PREVOTE";
/// Finality precommit domain.
pub const DOMAIN_PRECOMMIT: DomainTag = *b"NEUTRIN0_PRECOMM";
/// Explicit precommit proof-artifact and unlock commitments.
pub const DOMAIN_VOTE_ATTESTATION: DomainTag = *b"NEUTRIN0_VOTE___";
/// Signed chunk-level round-leader proposals.
pub const DOMAIN_BFT_PROPOSAL: DomainTag = *b"NEUTRIN0_BFTPROP";
/// Explicit nil votes, independently separated from value votes.
pub const DOMAIN_BFT_NIL: DomainTag = *b"NEUTRIN0_BFTNIL_";
/// Individual accountability declarations for nil votes.
pub const DOMAIN_BFT_NIL_ATTESTATION: DomainTag = *b"NEUTRIN0_NILATT_";
/// Signed pacemaker reports and their highest known quorum.
pub const DOMAIN_BFT_ROUND_CHANGE: DomainTag = *b"NEUTRIN0_ROUNDCH";
/// Domain for a proposer's signed publication of exact DA bundle bytes.
pub const DOMAIN_DA_PUBLICATION: DomainTag = *b"NEUTRIN0_DA_PUB_";
/// Validator registration proof-of-possession domain; see
/// [`registration_pop_message`].
pub const DOMAIN_DEPOSIT_POP: DomainTag = *b"NEUTRIN0_DEP_POP";
/// Aggregator-selection output domain.
pub const DOMAIN_AGG_PROOF: DomainTag = *b"NEUTRIN0_AGGPRF_";
/// Authenticated checkpoint endpoint identity.
pub const DOMAIN_CHECKPOINT: DomainTag = *b"NEUTRIN0_CHECKPT";
/// Occupied/empty history leaf commitment.
pub const DOMAIN_HISTORY_LEAF: DomainTag = *b"NEUTRIN0_HSTLEAF";
/// Internal history tree node commitment.
pub const DOMAIN_HISTORY_NODE: DomainTag = *b"NEUTRIN0_HSTNODE";
/// Counted history root commitment.
pub const DOMAIN_HISTORY_ROOT: DomainTag = *b"NEUTRIN0_HSTROOT";
/// Transaction tree leaf commitment.
pub const DOMAIN_TX_LEAF: DomainTag = *b"NEUTRIN0_TX_LEAF";
/// Transaction tree internal node commitment.
pub const DOMAIN_TX_NODE: DomainTag = *b"NEUTRIN0_TX_NODE";
/// Counted transaction root commitment.
pub const DOMAIN_TX_ROOT: DomainTag = *b"NEUTRIN0_TX_ROOT";
/// Certified precommit participation handed from consensus to the runtime.
pub const DOMAIN_PARTICIPATION: DomainTag = *b"NEUTRIN0_PARTICI";
/// Proving report commitments (design 08).
pub const DOMAIN_PROVING: DomainTag = *b"NEUTRIN0_PROVING";
/// Execution input commitments a header declares (design 08).
pub const DOMAIN_EXECUTION_INPUTS: DomainTag = *b"NEUTRIN0_EXEC_IN";
/// Commitment of a proposal's payment selection that every value vote signs
/// (design 08).
pub const DOMAIN_SELECTION: DomainTag = *b"NEUTRIN0_SELECTN";
/// Consensus boundary commitments that chain each boundary to its
/// predecessor (design 08).
pub const DOMAIN_BOUNDARY: DomainTag = *b"NEUTRIN0_BOUNDRY";
/// Commitment of the programs a specification pins at its start, by which
/// governance names a hard fork's successor (design 20).
pub const DOMAIN_PINNED_PROGRAMS: DomainTag = *b"NEUTRIN0_PINNED_";
/// Domain for counted transaction and vote DA commitments to counted body-lane Merkle roots.
pub const DOMAIN_DA_LANE: DomainTag = *b"NEUTRIN0_DA_____";

// Per-type tags of the generic Borsh commitment (`evidence::commitment`):
// one for every committed type, so separation never rests on encodings
// having different lengths.
/// Validator set (the validator-set root).
pub const DOMAIN_VALIDATORS: DomainTag = *b"NEUTRIN0_VALSET_";
/// Evidence anchor.
pub const DOMAIN_EVIDENCE_ANCHOR: DomainTag = *b"NEUTRIN0_EVANCHR";
/// Evidence context (the History leaf value).
pub const DOMAIN_EVIDENCE_CONTEXT: DomainTag = *b"NEUTRIN0_EVCTX__";
/// Evidence statement.
pub const DOMAIN_EVIDENCE_STATEMENT: DomainTag = *b"NEUTRIN0_EVSTMT_";
/// Compact participation acknowledgement in the vote lane.
pub const DOMAIN_PARTICIPATION_VOTE: DomainTag = *b"NEUTRIN0_PARTVOT";
/// Block proof envelope.
pub const DOMAIN_BLOCK_PROOF: DomainTag = *b"NEUTRIN0_BLKPROF";
/// Chunk receipt statement (a chunk proof's statement key).
pub const DOMAIN_CHUNK_STATEMENT: DomainTag = *b"NEUTRIN0_CHKSTMT";
/// Block receipt statement (a receipt's statement key).
pub const DOMAIN_BLOCK_STATEMENT: DomainTag = *b"NEUTRIN0_BLKSTMT";
/// Block proof public inputs (a block-proof leaf).
pub const DOMAIN_BLOCK_INPUTS: DomainTag = *b"NEUTRIN0_BLKINPT";
/// Program-lane piece descriptor.
pub const DOMAIN_PROGRAM_PIECE: DomainTag = *b"NEUTRIN0_PIECE__";
/// Carried previous-chunk certificate.
pub const DOMAIN_CARRIED_CERT: DomainTag = *b"NEUTRIN0_CARRIED";
/// Finality certificate.
pub const DOMAIN_FINALITY_CERT: DomainTag = *b"NEUTRIN0_FINCERT";
/// Evidence claim of an Evidence Guest witness.
pub const DOMAIN_EVIDENCE_CLAIM: DomainTag = *b"NEUTRIN0_EVCLAIM";
/// Mandatory sanction queue of the runtime.
pub const DOMAIN_SANCTION_QUEUE: DomainTag = *b"NEUTRIN0_SANCTNQ";
/// A value-vote attestation's statement identity.
pub const DOMAIN_ATTESTATION_ID: DomainTag = *b"NEUTRIN0_ATTESTN";
/// A nil-vote attestation's statement identity.
pub const DOMAIN_NIL_ATTESTATION_ID: DomainTag = *b"NEUTRIN0_NATTEST";
/// Evidence batch named by an Evidence Guest receipt.
pub const DOMAIN_EVIDENCE_BATCH: DomainTag = *b"NEUTRIN0_EVBATCH";
/// Fact Guest statement.
pub const DOMAIN_FACT_STATEMENT: DomainTag = *b"NEUTRIN0_FACTSTM";
/// A round-change report's statement identity.
pub const DOMAIN_ROUND_CHANGE_ID: DomainTag = *b"NEUTRIN0_RNDCHNG";
/// Chunk hash.
pub const DOMAIN_CHUNK: DomainTag = *b"NEUTRIN0_CHUNK__";
/// Block header hash.
pub const DOMAIN_HEADER: DomainTag = *b"NEUTRIN0_HEADER_";
/// Chain specification hash.
pub const DOMAIN_CHAIN_SPEC: DomainTag = *b"NEUTRIN0_SPEC___";
/// Round-leader draw digest; distinct from the proposal signing tag.
pub const DOMAIN_LEADER_DRAW: DomainTag = *b"NEUTRIN0_LEADER_";

/// Payload a validator registration's proof of possession signs under the
/// BLS POP cipher suite: `DOMAIN_DEPOSIT_POP || pubkey || address`.
///
/// Binding the registering address means a proof copied from someone else's
/// registration cannot seat their key at another address: only the holder of
/// the secret key can register it, and only where they chose.
#[must_use]
pub fn registration_pop_message(pubkey: &BlsPublicKey, address: &Hash) -> [u8; 96] {
    let mut message = [0; 96];
    message[..16].copy_from_slice(&DOMAIN_DEPOSIT_POP);
    message[16..64].copy_from_slice(pubkey);
    message[64..].copy_from_slice(address);
    message
}
