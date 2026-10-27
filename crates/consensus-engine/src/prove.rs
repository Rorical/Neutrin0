//! Per-block proof orchestration: the FSM transitions
//! `BlockProduced → PendingProof → Proven` for a single produced block.
//!
//! Production proofs use the SP1 Compressed STARK backend.

use core::fmt;
extern crate alloc;
use alloc::vec::Vec;

use neutrin0_consensus_types::{BlockProof as WireBlockProof, BlockProofPublicInputs, Header};
use neutrin0_primitives::{BlockHash, ChainId, Hash, StateRoot};
use neutrin0_proof_system::{ProofError, ProofSystem};

use crate::block_state::BlockState;
use crate::error::EngineError;
use crate::store::StoreError;

mod jobs;
mod public_inputs;

/// Failures while proving a single block.
#[derive(Debug)]
pub enum ProveError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
    /// The targeted block has no header on disk.
    UnknownBlock(BlockHash),
    /// The targeted block has not yet been produced (no FSM state at all).
    NoBlockState(BlockHash),
    /// The block is already past the proven state and cannot be re-proved.
    AlreadyAdvanced {
        /// Current FSM state.
        current: BlockState,
    },
    /// The parent header is required to bind `state_root_before` but is
    /// missing.
    MissingParentHeader {
        /// Hash of the parent header that could not be loaded.
        parent_hash: BlockHash,
    },
    /// The execution witness has not been persisted.
    MissingWitness(BlockHash),
    /// Header-committed body data needed to authenticate execution inputs is unavailable.
    MissingBody(BlockHash),
    /// Backend proof generation failed.
    Backend(ProofError),
    /// No prover address is configured and this node has no seat to name.
    NoProverAddress,
    /// Borsh-serialising the backend proof bytes for storage failed.
    Codec(borsh::io::Error),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for ProveError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProverAddress => f.write_str("no prover address: configure [proving] prover_address or run with a seated validator key"),
            Self::Engine(e) => write!(f, "engine error: {e}"),
            Self::UnknownBlock(hash) => write!(f, "block {hash:?} has no header on disk"),
            Self::NoBlockState(hash) => {
                write!(f, "block {hash:?} has no FSM state recorded yet")
            }
            Self::AlreadyAdvanced { current } => {
                write!(f, "block FSM is already past Proven (current = {current})")
            }
            Self::MissingParentHeader { parent_hash } => {
                write!(f, "parent header {parent_hash:?} is missing")
            }
            Self::MissingWitness(hash) => write!(f, "block {hash:?} has no execution witness"),
            Self::MissingBody(hash) => {
                write!(f, "block {hash:?} has no retained execution-context body")
            }
            Self::Backend(err) => write!(f, "proof backend error: {err:?}"),
            Self::Codec(err) => write!(f, "borsh encode of backend proof failed: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ProveError<E> {}

impl<E> From<EngineError<E>> for ProveError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for ProveError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}

impl<E> From<ProofError> for ProveError<E> {
    fn from(value: ProofError) -> Self {
        Self::Backend(value)
    }
}

impl<E> From<borsh::io::Error> for ProveError<E> {
    fn from(value: borsh::io::Error) -> Self {
        Self::Codec(value)
    }
}

/// Outcome of [`Engine::prove_block`](crate::Engine::prove_block): the wire proof, the public
/// inputs the backend bound, and the FSM state the engine settled on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProveOutcome {
    /// Block hash that was proven.
    pub block_hash: BlockHash,
    /// Committed state: `Proven`, or `Finalized` after concurrent finalization.
    pub state: BlockState,
    /// Wire-shaped block proof persisted in the store.
    pub block_proof: WireBlockProof,
    /// Public inputs the backend bound. Equal to
    /// `block_proof.public_inputs`; surfaced here so callers do not
    /// have to clone.
    pub public_inputs: BlockProofPublicInputs,
}

/// Immutable proving snapshot. It carries no engine lock or mutable state.
#[derive(Debug)]
pub struct BlockProofJob {
    header: Header,
    public_inputs: BlockProofPublicInputs,
    witness_bytes: Vec<u8>,
    bindings: Option<BlockStatementBindings>,
    /// Account the receipt will name for payment (design 08).
    prover_address: Hash,
}

/// Execution inputs authenticated by body lanes rather than header public inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockStatementBindings {
    anchor: neutrin0_consensus_types::evidence::EvidenceAnchor,
    participation: Hash,
    participation_acks: Hash,
    program_pieces: Hash,
}

impl BlockStatementBindings {
    pub(crate) fn matches_statement(
        &self,
        statement: &neutrin0_runtime_abi::RuntimeBlockOutput,
    ) -> bool {
        statement.accountability.anchor == self.anchor
            && statement.participation == self.participation
            && statement.participation_acks == self.participation_acks
            && statement.program_pieces == self.program_pieces
    }
}

/// Result constructed only after proof verification against the snapshotted inputs.
#[derive(Debug)]
pub struct CompletedBlockProof {
    job: BlockProofJob,
    proof: WireBlockProof,
}

impl BlockProofJob {
    /// Run expensive proving and verification outside the engine mutex.
    pub fn prove<PS: ProofSystem>(self, backend: &PS) -> Result<CompletedBlockProof, ProofError> {
        let proof = backend.prove_block(
            &self.witness_bytes,
            &self.public_inputs,
            self.prover_address,
        )?;
        let statement = backend.verify_block_statement(&proof, &self.public_inputs)?;
        if statement.prover_address != self.prover_address {
            return Err(ProofError::PublicInputMismatch);
        }
        if let Some(bindings) = &self.bindings
            && !bindings.matches_statement(&statement.output)
        {
            return Err(ProofError::PublicInputMismatch);
        }
        let proof = WireBlockProof {
            height: self.header.height,
            block_hash: self.public_inputs.block_hash,
            public_inputs: self.public_inputs.clone(),
            proof_bytes: borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)?,
            prover_address: statement.prover_address,
            statement_key: statement_key(&statement),
        };
        Ok(CompletedBlockProof { job: self, proof })
    }
}

/// Statement key of a receipt: the commitment of its complete public values,
/// shared by every proof of one statement and distinct for every attribution.
#[must_use]
pub fn statement_key(statement: &neutrin0_runtime_abi::BlockReceiptStatement) -> Hash {
    neutrin0_consensus_types::evidence::commitment(statement)
}

/// Fill a receipt record's attribution from its verified statement.
pub(crate) fn attribute(
    proof: &mut WireBlockProof,
    statement: &neutrin0_runtime_abi::BlockReceiptStatement,
) {
    proof.prover_address = statement.prover_address;
    proof.statement_key = statement_key(statement);
}

/// Block-proof public inputs binding `header` to an exact runtime artifact,
/// Block Guest and proposer account.
pub(crate) fn header_public_inputs(
    context: &neutrin0_consensus_types::runtime::ConsensusExecutionContext,
    chain_id: ChainId,
    header: &Header,
    state_root_before: StateRoot,
    block_hash: BlockHash,
    programs: &neutrin0_primitives::ProgramSet,
    proposer_address: Hash,
) -> BlockProofPublicInputs {
    BlockProofPublicInputs {
        context: (*context).into(),
        chain_id,
        height: header.height,
        parent_block_hash: header.parent_hash,
        block_hash,
        state_root_before,
        state_root_after: header.state_root,
        transactions_root: header.transactions_root,
        receipt_root: header.receipts_root,
        da_root: header.da_root,
        vm_code_hash: programs.runtime_code_hash,
        block_program: programs.execution.block,
        gas_used: header.gas_used,
        gas_limit: header.gas_limit,
        proposer_address,
        runtime_extra: header.runtime_extra,
        inputs_root: header.inputs_root,
    }
}
