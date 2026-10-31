//! Complete consensus chunk preparation and atomic, proof-gated finalization.

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::Chunk;
use neutrin0_consensus_types::history_proof::ChainBinding;
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_prover_chunk::{
    consensus::{ConsensusWitness, ValidatedCandidate},
    execution::ExecutionContext,
};
use neutrin0_storage::Database;

use crate::Engine;

mod carried_reports;
mod commit;
mod evidence;
mod participation_votes;
mod preparation;
mod ratification;
mod sanctions;
mod witness;

pub use preparation::PendingConsensusChunk;

/// Outgoing consensus context, stored separately for certification and finality.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusState {
    /// Outgoing boundary. Only the finalized store authenticates proof finality;
    /// the certified execution record retains native validation separately.
    pub boundary: neutrin0_consensus_types::history_proof::ConsensusBoundary,
    /// Full context retained for ordinary execution, checked against the compact output.
    pub next_context: ExecutionContext,
    /// Randomness for the following chunk.
    pub next_seed: Hash,
    /// Bounded append frontier; historical records live in the archive.
    pub frontier: neutrin0_consensus_types::history::HistoryFrontier,
}

/// A gathered, not yet validated witness with its verified block receipts.
type BranchWitness<P> = (ConsensusWitness, Vec<<P as ProofSystem>::BlockProof>);

/// The public inputs committing `chunk`, field for field.
const fn chunk_public_inputs(chunk: &Chunk) -> neutrin0_consensus_types::ChunkProofPublicInputs {
    neutrin0_consensus_types::ChunkProofPublicInputs {
        chunk_id: chunk.chunk_id,
        start_height: chunk.start_height,
        end_height: chunk.end_height,
        start_state_root: chunk.start_state_root,
        end_state_root: chunk.end_state_root,
        start_block_hash: chunk.start_block_hash,
        end_block_hash: chunk.end_block_hash,
        block_hash_root: chunk.block_hash_root,
        block_proof_root: chunk.block_proof_root,
        vrf_proof_root: chunk.vrf_proof_root,
        active_validator_set_root: chunk.active_validator_set_root,
        next_validator_set_root: chunk.next_validator_set_root,
        next_identity_sanctions_root: chunk.next_identity_sanctions_root,
        da_root: chunk.da_root,
    }
}

/// Immutable snapshot carried outside the engine lock for expensive proving.
pub struct PreparedConsensusChunk<P: ProofSystem> {
    /// Fully bound candidate, with certificate filled before proving.
    pub witness: ConsensusWitness,
    /// Candidate validation of `witness` at preparation. Candidate validation
    /// never reads the certificate, the only field filled afterwards.
    pub candidate: ValidatedCandidate,
    /// Inner proofs in exact canonical height order.
    pub proofs: Vec<P::BlockProof>,
    /// The held chunk proofs the installed certificate ratifies, a prefix of
    /// the witness's `ratified` statements; proving needs all of them, while
    /// validation needs only the statements (design 08).
    pub ratified: Vec<P::ChunkProof>,
}

impl<P: ProofSystem> PreparedConsensusChunk<P> {
    /// The first ratified chunk proof the certificate names that this node
    /// does not hold, as its chunk id and statement key. Proving requires
    /// none to be missing.
    #[must_use]
    pub fn missing_ratified_proof(&self) -> Option<(ChunkId, Hash)> {
        self.witness
            .finality_cert
            .proposal
            .ratified_chunk_proofs
            .get(self.ratified.len())
            .map(|entry| (entry.chunk_id, entry.statement_key))
    }
}

/// The participation and proving reports a block consumes from the previous
/// chunk's carried certificate (design 08).
pub type CarriedReports = (
    neutrin0_consensus_types::participation::ParticipationReport,
    neutrin0_consensus_types::proving::ProvingReport,
);

impl<DB: Database> Engine<DB> {
    /// Enable chunk consensus under the configured proof backend. Its chunk
    /// Guest must be the one the specification pins: the backend derived it
    /// locally, the specification decides it. Returns `false`, enabling
    /// nothing, for any other backend. The genesis program set is the
    /// specification's, never the backend's.
    pub fn set_programs(
        &mut self,
        guests: neutrin0_consensus_types::history_proof::GuestPrograms,
    ) -> bool {
        if guests.chunk != self.chain_spec().genesis_chunk {
            return false;
        }
        self.programs = Some(self.chain_spec().genesis_programs());
        true
    }

    /// The immutable chain binding: the specification's commitment.
    #[must_use]
    pub const fn chain_binding(&self) -> ChainBinding {
        ChainBinding::with_hash(self.chain_spec_hash())
    }

    /// The genesis boundary's program set: the pinned Guests bound to the
    /// specification's runtime. Without a proof backend the Guests are zero;
    /// such a node can serve and import blocks but never proves, verifies or
    /// agrees on a chunk statement, because incomplete sets fail validation.
    pub const fn genesis_programs(&self) -> neutrin0_consensus_types::history_proof::ProgramSet {
        neutrin0_primitives::ProgramSet {
            runtime_code_hash: self.chain_spec().runtime_code_hash,
            execution: self.chain_spec().genesis_execution,
        }
    }
}
