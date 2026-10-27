//! Block-execution trait used by the consensus engine's
//! `try_produce_block` path.
//!
//! The trait is symmetric to [`ProofSystem`]: both are stateless
//! seams the engine calls into. `BlockExecutor` is responsible for
//! the dynamic execution side (the WASM runtime); the
//! matching `ProofSystem::prove_block` consumes the witness this
//! trait emits and produces an SP1 Compressed STARK proof bound to
//! the same transition.
//!
//! [`ProofSystem`]: super::ProofSystem

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use neutrin0_consensus_types::Body;
use neutrin0_primitives::{Hash, StateRoot};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrin0_trie::{Poseidon2Hasher, Trie};

mod erased;
#[cfg(test)]
mod tests;

pub use erased::ErasedBlockExecutor;

/// Per-block consensus context passed to [`BlockExecutor::execute_block`].
///
/// Bundles the engine-supplied fields the runtime needs to execute
/// one block correctly: chain identity, header height, gas ceiling,
/// and the proposer's runtime account address (fee
/// recipient). Grouping them keeps the trait signature compact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockExecutionContext {
    /// Header facts and the finalized boundary entering this chunk.
    pub context: neutrin0_consensus_types::runtime::ConsensusExecutionContext,
    /// Active committee authenticated by this block's incoming boundary.
    pub active_validators: Vec<neutrin0_primitives::Validator>,
    /// Trusted prior consensus context and accepted evidence/block programs.
    pub evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor,
    /// Runtime artifact the block executes under: the runtime code hash of
    /// its chunk boundary's program set (design 20).
    pub runtime_code_hash: Hash,
    /// Chain identifier the transactions are bound to.
    pub chain_id: u64,
    /// Height of the block being executed (`header.height`).
    pub block_height: u64,
    /// Block-level gas ceiling (`header.gas_limit`).
    pub gas_limit: u64,
    /// Runtime account that receives the block's accumulated fees.
    /// The engine sources it from
    /// `active_validator_set[header.proposer_index].withdrawal_credentials`.
    pub proposer_address: Hash,
    /// Certified precommit participation of the previous chunk, taken from the
    /// certificate the chunk's carrier block holds: `None` in the first chunk
    /// and before the carrier, then the same for the carrier and every later
    /// block of the chunk (design 08). The chunk Guest checks the runtime's
    /// commitment against the chunk boundary.
    pub participation: Option<neutrin0_consensus_types::participation::ParticipationReport>,
    /// Certified proving report of the previous chunk, derived from the same
    /// carried certificate and present exactly when `participation` is.
    pub proving: Option<neutrin0_consensus_types::proving::ProvingReport>,
    /// Positive participation authenticated from the body's historical vote lane.
    pub participation_acks:
        Vec<neutrin0_consensus_types::participation::ParticipationAcknowledgement>,
    /// References of the body's program-lane pieces (design 20).
    pub program_pieces: Vec<neutrin0_consensus_types::ProgramPieceRef>,
}

impl BlockExecutionContext {
    /// The execution-input commitment a header built in this context declares
    /// (design 08); the runtime's output reproduces it.
    #[must_use]
    pub fn inputs_root(&self) -> Hash {
        execution_inputs_commitment(
            &self.context,
            self.participation.as_ref(),
            &self.participation_acks,
            self.proving.as_ref(),
            &self.program_pieces,
            &self.evidence_anchor,
        )
    }
}

/// The execution-input commitment of a block (design 08).
///
/// It covers `context`, the carried reports, the acknowledged participation,
/// the program-lane references and `evidence_anchor`. A block before its
/// chunk's carrier consumes no new report and commits the start boundary's.
/// It needs no runtime artifact, so a node that does not execute derives it
/// as well.
#[must_use]
pub fn execution_inputs_commitment(
    context: &neutrin0_consensus_types::runtime::ConsensusExecutionContext,
    participation: Option<&neutrin0_consensus_types::participation::ParticipationReport>,
    participation_acks: &[neutrin0_consensus_types::participation::ParticipationAcknowledgement],
    proving: Option<&neutrin0_consensus_types::proving::ProvingReport>,
    program_pieces: &[neutrin0_consensus_types::ProgramPieceRef],
    evidence_anchor: &neutrin0_consensus_types::evidence::EvidenceAnchor,
) -> Hash {
    let boundary = &context.finalized;
    neutrin0_consensus_types::runtime::execution_inputs_root(
        context,
        participation.map_or(
            boundary.participation,
            neutrin0_consensus_types::participation::ParticipationReport::commitment,
        ),
        neutrin0_consensus_types::participation::acknowledgement_commitment(participation_acks),
        proving.map_or(
            boundary.proving,
            neutrin0_consensus_types::proving::ProvingReport::commitment,
        ),
        neutrin0_consensus_types::program_pieces_commitment(program_pieces),
        evidence_anchor,
    )
}

/// Outcome of a successful [`BlockExecutor::execute_block`] call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    /// Runtime-specific receipts and metadata authenticated by `receipts_root`.
    pub artifacts: neutrin0_runtime_abi::ExecutionArtifacts,
    /// Post-execution state root. Matches the root of the mutated
    /// state trie the executor returned through `&mut state`.
    pub state_root_after: StateRoot,
    /// Runtime-defined commitment the engine wires into
    /// `header.runtime_extra`. For the default runtime this is the
    /// canonical `consensus_candidates_root` so the next chunk BFT picks up
    /// the updated stake distribution.
    pub runtime_extra: Hash,
    /// Runtime-emitted per-block receipts-root commitment. The engine
    /// wires this into `header.receipts_root` and
    /// `BlockProofPublicInputs.receipt_root` so the SP1 proof binds
    /// the same value the header carries.
    pub receipts_root: Hash,
    /// Gas the block consumed: every included transaction, reverted or halted
    /// ones too, plus system gas. The engine
    /// wires this into `header.gas_used` and
    /// `BlockProofPublicInputs.gas_used` so the SP1 proof commits to
    /// the same value the header carries.
    pub gas_used: u64,
    /// Opaque blob suitable for the matching
    /// `ProofSystem::prove_block`. For the SP1 + EVM runtime
    /// pairing this is the borsh-encoded runtime input, state witness and
    /// evidence attachments. The prover supplies attachments separately to recursion.
    pub witness_bytes: Vec<u8>,
    /// Final value of every state key the block wrote, in strictly
    /// increasing key order. Applying these writes to the pre-state trie
    /// reproduces `state_root_after`; proof-following nodes consume them
    /// instead of executing the body.
    pub state_writes: Vec<neutrin0_consensus_types::StateWrite>,
}

/// Backend-agnostic block-execution interface.
///
/// Implementations drive the dynamic WASM runtime against
/// the engine's authoritative state trie, mutate the trie with the
/// block's writes, and emit an opaque witness blob the matching
/// proof system can replay.
///
/// `state` is the engine's live state trie. On success the trie has
/// been advanced to `state_root_after`. On failure the trie must be
/// left untouched so the engine can safely retry production at the
/// next slot.
pub trait BlockExecutor {
    /// Keep installed runtime modules alive through asynchronous state/bootstrap work.
    /// # Errors
    /// Returns the executor's unavailable-program or resource failure.
    fn lease_runtimes(
        &self,
        _runtimes: &[Hash],
    ) -> Result<crate::artifacts::ProgramLease, Self::Error> {
        Ok(alloc::sync::Arc::new(()))
    }

    /// Evict obsolete compiled modules while retaining authenticated reloadable sources.
    fn retain_programs(&self, _retention: &crate::artifacts::ProgramRetention) {}

    /// Supply a bounded reader for locally authenticated historical WASM artifacts.
    fn set_artifact_loader(&self, _loader: crate::artifacts::ProgramArtifactLoader) {}

    /// Executor-specific error type.
    type Error: fmt::Debug + fmt::Display;

    /// Execute a block body against `state` and return the post-state
    /// commitments + witness bytes.
    ///
    /// `ctx` carries the engine-supplied consensus context (chain
    /// id, block height, gas ceiling, proposer fee recipient and carried
    /// reports). See [`BlockExecutionContext`] for the per-field
    /// meaning and how the engine sources each value.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the runtime fails to load, the
    /// body cannot be decoded, or the dry-run traps.
    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error>;

    /// Run a read-only [`QueryRequest`] against `state`.
    ///
    /// Implementations MUST NOT mutate `state`; queries that
    /// attempt writes are rejected by the runtime host with
    /// [`neutrin0_runtime_abi::QueryStatus::PermissionDenied`].
    /// The returned [`QueryResponse`] carries the runtime-defined
    /// status code and payload (status `0` = success per
    /// [`neutrin0_runtime_abi::QueryStatus::Ok`]).
    ///
    /// # Errors
    /// Returns [`Self::Error`] if the runtime fails to load, the
    /// query traps inside the runtime, or codec failure prevents the
    /// host from decoding the response. Runtime-defined query
    /// failures (unknown method, malformed args, etc.) are surfaced
    /// as non-zero [`QueryResponse::code`] values, not as
    /// `Self::Error`.
    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, Self::Error>;

    /// Exact bytes of an installed runtime, for bounded bootstrap artifact
    /// serving. Unknown artifacts remain unavailable; this never installs code.
    fn runtime_artifact(&self, _runtime_code_hash: &Hash) -> Option<Vec<u8>> {
        None
    }

    /// Read at most 64 KiB of an installed runtime, returning its total byte
    /// length and the fragment at `offset`. Unknown programs remain unavailable.
    fn runtime_fragment(
        &self,
        code_hash: &Hash,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, Vec<u8>)> {
        crate::artifacts::artifact_fragment(&self.runtime_artifact(code_hash)?, offset, max_bytes)
    }

    /// Mempool / RPC admission check for a single candidate
    /// transaction.
    ///
    /// Runs the runtime's `_neutrin0_validate_tx` entrypoint
    /// against a read-only view of `state`. Returns the canonical
    /// [`TxValidity`] result the runtime emitted: a
    /// [`TxValidationCode`](neutrin0_runtime_abi::TxValidationCode)
    /// describing whether (and why not) the transaction is
    /// admissible, plus a mempool priority for the `Valid` case.
    ///
    /// The per-gas fee comes from the runtime policy held in `state`,
    /// so the balance check covers `tx.amount + tx_gas * gas_price`
    /// under the policy that will apply to the next block.
    ///
    /// Implementations MUST NOT mutate `state` and MUST NOT depend on
    /// non-deterministic inputs: the same `(tx, state, chain_id,
    /// block_gas_limit)` tuple must always produce the
    /// same result so peers cannot disagree about admission outcomes.
    ///
    /// # Errors
    /// Returns [`Self::Error`] when the runtime traps or the host
    /// fails to decode the runtime's 12-byte response.
    /// Runtime-defined rejections (bad signature, nonce mismatch,
    /// ...) are surfaced through [`TxValidity::code`], not as
    /// `Self::Error`.
    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, Self::Error>;

    /// Install a runtime artifact distributed on chain (design 20) and return
    /// its code hash. Executors with one fixed runtime refuse.
    ///
    /// # Errors
    /// Surfaces executor-specific failures.
    fn install_runtime(&self, _wasm: &[u8]) -> Result<Hash, Self::Error>;

    /// Code hashes of every installed runtime.
    fn installed_runtimes(&self) -> Vec<Hash>;
}

/// Convenience [`BlockExecutor`] implementation that returns an
/// `Unsupported` error from every call.
///
/// Used by tests and consensus crates that need a `BlockExecutor` in
/// the type signature but never exercise it.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedExecutor;

impl BlockExecutor for UnsupportedExecutor {
    type Error = String;

    fn execute_block(
        &self,
        _ctx: &BlockExecutionContext,
        _body: &Body,
        _state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn query(
        &self,
        _request: &QueryRequest,
        _runtime_code_hash: Hash,
        _state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn validate_tx(
        &self,
        _tx_bytes: &[u8],
        _chain_id: u64,
        _block_gas_limit: u64,
        _runtime_code_hash: Hash,
        _state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, Self::Error> {
        // Without an executor the system has no way to interpret the
        // bytes, so report a definitive failure rather than silently
        // admitting an opaque blob. Mempool admission keys on the
        // returned `TxValidationCode`, not on the error path.
        Err(String::from("block executor not configured"))
    }

    fn install_runtime(&self, _wasm: &[u8]) -> Result<Hash, Self::Error> {
        Err(String::from("block executor not configured"))
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        Vec::new()
    }
}
