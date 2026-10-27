//! The canonical chain specification and its hard-fork anchor.

mod error;
mod validation;

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

pub use error::ChainSpecError;

use crate::{
    BlockHash, BlsPublicKey, BoundedBytes, ChainId, ConsensusBoundary, ConsensusDomain,
    ConsensusParams, Epoch, ExecutionPrograms, GenesisArtifacts, Hash, LightClientParams,
    MAX_CHAIN_NAME_BYTES, MAX_METADATA_BYTES, PinnedPrograms, PriorDomain, PriorDomains,
    ProgramSet, ProofParams, RuntimeParams, ScheduledFork, Seed, StateRoot, blake3_256,
};

/// Runtime metadata exposed by the runtime query API.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeInfo {
    /// Fixed-width runtime name.
    pub spec_name: [u8; 16],
}

impl Default for RuntimeInfo {
    /// Chain-spec metadata label. The installed runtime answers the
    /// `runtime_info` query with its own name; the EVM runtime reports
    /// `NEUTRIN0_EVM`.
    fn default() -> Self {
        Self {
            spec_name: *b"NEUTRIN0_DEFAULT",
        }
    }
}

/// Validator identity and activation metadata from the active validator set.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Validator {
    /// BLS signing public key.
    pub pubkey: BlsPublicKey,
    /// Runtime-defined withdrawal credential commitment.
    pub withdrawal_credentials: Hash,
    /// Consensus weight in wei. Genesis weights are specification stakes;
    /// rotation projects runtime stakes unchanged.
    pub effective_stake: u128,
    /// Epoch at which the validator becomes active.
    pub activation_epoch: Epoch,
    /// Epoch at which the validator exits.
    pub exit_epoch: Epoch,
}

/// Canonical chain specification used for DB metadata and peer compatibility.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChainSpec {
    /// Human-readable chain name.
    pub name: BoundedBytes<MAX_CHAIN_NAME_BYTES>,
    /// Chain identifier.
    pub chain_id: ChainId,
    /// Genesis timestamp in seconds since UNIX epoch.
    pub genesis_time: u64,
    /// Genesis block gas limit.
    pub genesis_gas_limit: u64,
    /// Runtime metadata expected at genesis.
    pub runtime_info: RuntimeInfo,
    /// BLAKE3 hash of the WASM runtime artifact bytes.
    pub runtime_code_hash: Hash,
    /// Complete genesis Fact, Evidence and Block Guest identities. Runtime selection
    /// never takes execution identities from an unauthenticated binary preference.
    /// With a fork anchor these are the programs the first post-fork chunk runs.
    pub genesis_execution: ExecutionPrograms,
    /// The chunk Guest every chunk receipt of this chain is verified under. It
    /// never changes: a new chunk Guest is a new specification (a hard fork).
    pub genesis_chunk: [u32; 8],
    /// Program-lane content hashes of the starting artifacts, so a node that does
    /// not embed them can fetch them by hash; zero where not distributed. Bytes
    /// are accepted only when their runtime hash or locally derived key matches.
    pub genesis_artifacts: GenesisArtifacts,
    /// Hard-fork anchor; `None` for a chain whose History starts at genesis.
    pub fork: Option<alloc::boxed::Box<ForkAnchor>>,
    /// Public randomness seed for the first post-genesis chunk.
    pub genesis_seed: Seed,
    /// State root returned by `runtime.init_genesis`.
    pub genesis_state_root: StateRoot,
    /// Header hash of the genesis block.
    pub genesis_block_hash: BlockHash,
    /// Validator-set root effective at genesis.
    pub genesis_validator_set_root: Hash,
    /// Consensus constants.
    pub consensus: ConsensusParams,
    /// Proof constants.
    pub proof: ProofParams,
    /// Light-client constants.
    pub light_client: LightClientParams,
    /// Runtime-execution constants (fee market, etc.).
    pub runtime: RuntimeParams,
    /// Initial validator set.
    pub initial_validators: Vec<Validator>,
    /// Optional metadata URL or label.
    pub metadata: BoundedBytes<MAX_METADATA_BYTES>,
}

/// Where a hard-forked specification starts (design 20).
///
/// Changing the chunk Guest, the Fact Guest or the SP1 version is a new chain
/// specification. Its History starts at `start`, trusted exactly as a genesis
/// boundary is: the first chunk it proves is `count` and starts there.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ForkAnchor {
    /// Complete hash of the specification this one replaces.
    pub predecessor: Hash,
    /// First chunk this specification proves; every lower chunk belongs to a
    /// predecessor.
    pub count: u64,
    /// Programs of the predecessor's authenticated boundary at `count`. With
    /// `start` they give that boundary whole ([`ChainSpec::fork_endpoint`]).
    pub endpoint_programs: ProgramSet,
    /// The boundary the first chunk starts from:
    /// [`ConsensusBoundary::fork_start`] of the endpoint.
    pub start: ConsensusBoundary,
    /// Runtime account of the prover of the predecessor's endpoint receipt,
    /// the proof of chunk `count - 1`. Chunk `count` ratifies no proof, since
    /// its Guest cannot verify the predecessor's, so its report credits this
    /// account with that chunk's prover share instead.
    pub endpoint_prover: Hash,
    /// Signing domains of every predecessor, oldest first; the last is
    /// `predecessor`'s and ends at `count`.
    pub prior_domains: Vec<PriorDomain>,
}

impl ChainSpec {
    /// The predecessor's authenticated boundary at a fork's count, which its
    /// History proof of chunk `count - 1` ends at: `start` with the
    /// predecessor's programs and the fork that ended it, scheduled for this
    /// specification's pinned programs. `None` without a fork.
    #[must_use]
    pub fn fork_endpoint(&self) -> Option<ConsensusBoundary> {
        let fork = self.fork.as_deref()?;
        Some(ConsensusBoundary {
            programs: fork.endpoint_programs,
            fork: Some(ScheduledFork {
                count: fork.count,
                successor: self.pinned_programs().commitment(),
            }),
            ..fork.start
        })
    }

    /// The programs this specification pins at its start.
    #[must_use]
    pub const fn pinned_programs(&self) -> PinnedPrograms {
        PinnedPrograms {
            programs: self.genesis_programs(),
            chunk: self.genesis_chunk,
            artifacts: self.genesis_artifacts,
        }
    }

    /// Bind consensus signatures to this complete specification, keeping its
    /// predecessors' domains for signatures on older chunks.
    #[must_use]
    pub fn consensus_domain(&self) -> ConsensusDomain {
        self.consensus_domain_with(self.hash())
    }

    /// [`Self::consensus_domain`] with `chain_spec_hash == self.hash()` already
    /// computed.
    #[must_use]
    pub fn consensus_domain_with(&self, chain_spec_hash: Hash) -> ConsensusDomain {
        ConsensusDomain {
            chain_id: self.chain_id,
            chain_spec_hash,
            // Validation refuses a specification with more predecessor
            // domains than `PriorDomains` holds, so none is dropped here.
            prior: self
                .fork
                .as_ref()
                .and_then(|fork| PriorDomains::from_slice(&fork.prior_domains))
                .unwrap_or(PriorDomains::NONE),
        }
    }

    /// First chunk this specification proves: zero, or its fork anchor's count.
    #[must_use]
    pub fn first_chunk(&self) -> u64 {
        self.fork.as_ref().map_or(0, |fork| fork.count)
    }

    /// The chunk whose proof a certificate of `chunk_id` ratifies; `None` for
    /// the first chunk, which starts at a pinned boundary.
    #[must_use]
    pub fn previous_chunk(&self, chunk_id: u64) -> Option<u64> {
        (chunk_id > self.first_chunk()).then(|| chunk_id - 1)
    }

    /// The chunk whose certificate a block of `chunk_id` carries: the one
    /// before it, but none for chunk 0. A hard fork's first chunk carries its
    /// predecessor's last, whose reports would otherwise never settle, without
    /// ratifying that chunk's proof.
    #[must_use]
    pub const fn carried_chunk(&self, chunk_id: u64) -> Option<u64> {
        chunk_id.checked_sub(1)
    }

    /// The chunk prover a report of `chunk_id` credits beyond its own
    /// ratifications: the fork's endpoint prover, for the fork's first chunk.
    #[must_use]
    pub fn pinned_chunk_prover(&self, chunk_id: u64) -> Option<(u64, Hash)> {
        let fork = self.fork.as_ref().filter(|fork| fork.count == chunk_id)?;
        Some((chunk_id.checked_sub(1)?, fork.endpoint_prover))
    }

    /// Authenticate complete execution identities against the immutable Fact
    /// pin.
    #[must_use]
    pub fn accepts_programs(&self, programs: &ProgramSet) -> bool {
        programs.is_complete() && programs.execution.fact == self.genesis_execution.fact
    }

    /// The programs this specification starts with.
    #[must_use]
    pub const fn genesis_programs(&self) -> ProgramSet {
        ProgramSet {
            runtime_code_hash: self.runtime_code_hash,
            execution: self.genesis_execution,
        }
    }

    /// Computes `BLAKE3(DOMAIN_CHAIN_SPEC || borsh(self))`, the canonical
    /// chain-spec hash.
    pub fn hash(&self) -> Hash {
        let mut bytes = crate::DOMAIN_CHAIN_SPEC.to_vec();
        self.serialize(&mut bytes)
            .expect("borsh serialization of ChainSpec is infallible");
        blake3_256(&bytes)
    }
}
