//! The immutable chain binding and the boundary between two chunks.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::hashing::tagged_commitment;
use crate::{
    ChainSpec, DOMAIN_BOUNDARY, EMPTY_HISTORY_ROOT, ExecutionPrograms, Hash, ProgramSet, Seed,
    ZERO_HASH,
};

/// Immutable chain identity authenticated by the consumer: the complete
/// specification commitment.
///
/// Everything immutable about the chain (its id, chunk size, Fact Guest and
/// the chunk Guest every chunk receipt is verified under) is a field of that
/// specification, so a consumer that holds the specification reads those
/// values from it and compares only this hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ChainBinding {
    /// Canonical complete specification commitment.
    pub chain_spec_hash: Hash,
}

impl ChainBinding {
    /// The consumer's validated specification.
    #[must_use]
    pub fn new(spec: &ChainSpec) -> Self {
        Self::with_hash(spec.hash())
    }

    /// [`Self::new`] with `chain_spec_hash == spec.hash()` already computed.
    #[must_use]
    pub const fn with_hash(chain_spec_hash: Hash) -> Self {
        Self { chain_spec_hash }
    }
}

/// A hard fork governance scheduled (design 20): the chain proves no chunk
/// from `count` on, and its successor pins the programs `successor` commits
/// ([`PinnedPrograms::commitment`](crate::PinnedPrograms::commitment)).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ScheduledFork {
    /// First chunk the successor proves.
    pub count: u64,
    /// Commitment of the programs the successor pins at its start.
    pub successor: Hash,
}

/// Authenticated state immediately before the next chunk; 409 Borsh bytes, 449
/// with a scheduled fork.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusBoundary {
    /// Next chunk to execute.
    pub next_chunk_id: u64,
    /// Height of the preceding block.
    pub height: u64,
    /// Hash of that preceding block.
    pub block_hash: Hash,
    /// State root after that block.
    pub state_root: Hash,
    /// Slot of that block.
    pub slot: u64,
    /// Canonical ordered active validator commitment.
    pub validators_root: Hash,
    /// Independent append-only trie of permanently sanctioned BLS identities.
    /// Execution programs cannot erase this consensus-owned state.
    pub identity_sanctions_root: Hash,
    /// Finalized randomness for the next chunk.
    pub seed: Seed,
    /// Counted authenticated history root.
    pub history_root: Hash,
    /// Programs that execute and prove the next chunk.
    pub programs: ProgramSet,
    /// Commitment of the latest participation report
    /// consumed by the chunk ending here. Its carrier block selected the
    /// previous chunk's certificate in committed data. This value is independent of the
    /// ending chunk's certificate subset; zero at genesis and after chunk zero.
    pub participation: Hash,
    /// Commitment of the latest proving report consumed by
    /// the chunk ending here, derived from the same carried certificate as
    /// `participation` (design 08); zero until one is.
    pub proving: Hash,
    /// The hard fork scheduled in the state this boundary follows, while its
    /// count is not behind `next_chunk_id`. At the count this boundary is the
    /// chain's endpoint, and no chunk starts from it.
    pub fork: Option<ScheduledFork>,
}
impl ConsensusBoundary {
    /// Domain-separated commitment of the boundary; History leaves record a
    /// chunk's start boundary by it.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        tagged_commitment(&DOMAIN_BOUNDARY, self)
    }

    /// Canonical genesis boundary under `programs`; callers validate the spec first.
    #[must_use]
    pub const fn genesis(spec: &ChainSpec) -> Self {
        Self {
            next_chunk_id: 0,
            height: 0,
            block_hash: spec.genesis_block_hash,
            state_root: spec.genesis_state_root,
            slot: 0,
            validators_root: spec.genesis_validator_set_root,
            identity_sanctions_root: ZERO_HASH,
            seed: spec.genesis_seed,
            history_root: EMPTY_HISTORY_ROOT,
            programs: ProgramSet {
                runtime_code_hash: spec.runtime_code_hash,
                execution: spec.genesis_execution,
            },
            participation: ZERO_HASH,
            proving: ZERO_HASH,
            fork: None,
        }
    }

    /// The boundary `spec`'s History starts from, trusted from the specification
    /// alone: genesis, or a hard fork's pinned start (design 20).
    #[must_use]
    pub fn first(spec: &ChainSpec) -> Self {
        spec.fork
            .as_ref()
            .map_or_else(|| Self::genesis(spec), |fork| fork.start)
    }

    /// The boundary a forked `spec` starts from: the predecessor's History
    /// endpoint `endpoint` with `spec`'s starting programs and without the
    /// fork that ended the predecessor there. Its chunk is the
    /// specification's first, which ratifies nothing.
    #[must_use]
    pub const fn fork_start(endpoint: &Self, spec: &ChainSpec) -> Self {
        Self {
            programs: spec.genesis_programs(),
            fork: None,
            ..*endpoint
        }
    }

    /// Whether this chain proves `chunk_id` from here: not at or beyond a
    /// scheduled fork's count.
    #[must_use]
    pub fn proves(&self, chunk_id: u64) -> bool {
        self.fork.is_none_or(|fork| chunk_id < fork.count)
    }

    /// Check the programs against `spec`'s Fact pin and the height/count
    /// relation with checked arithmetic.
    #[must_use]
    pub fn is_well_formed(&self, spec: &ChainSpec) -> bool {
        spec.accepts_programs(&self.programs)
            && self.next_chunk_id.checked_mul(spec.consensus.chunk_size) == Some(self.height)
    }
}

impl Default for ConsensusBoundary {
    fn default() -> Self {
        Self {
            next_chunk_id: 0,
            height: 0,
            block_hash: [0; 32],
            state_root: [0; 32],
            slot: 0,
            validators_root: crate::validators_root(&[]),
            identity_sanctions_root: ZERO_HASH,
            seed: [0; 32],
            history_root: EMPTY_HISTORY_ROOT,
            programs: ProgramSet {
                runtime_code_hash: [0; 32],
                execution: ExecutionPrograms {
                    fact: [0; 8],
                    evidence: [0; 8],
                    block: [0; 8],
                },
            },
            participation: ZERO_HASH,
            proving: ZERO_HASH,
            fork: None,
        }
    }
}
