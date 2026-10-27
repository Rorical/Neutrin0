//! History proofs: finalized chunk receipts, which recursively prove the
//! chain from the specification's start, and the openings that anchor later
//! trust in them.

use crate::{Engine, FinalizeError};
use neutrin0_consensus_types::history_proof::{
    AnchorOpening, ChunkReceiptStatement, ConsensusBoundary, ProofDomain,
};
use neutrin0_consensus_types::{ChunkProof, HistoryProof};
use neutrin0_primitives::BoundedBytes;
use neutrin0_proof_system::ProofError;
use neutrin0_storage::Database;

/// The History proof a finalized chunk receipt forms: the receipt without its
/// certificate. `statement` must be the receipt's stored consensus statement.
///
/// # Errors
/// Returns [`ProofError::PublicInputMismatch`] when the statement does not
/// describe the receipt's chunk and certificate, and
/// [`ProofError::MalformedProof`] when the receipt exceeds the History bound.
pub fn history_proof_of(
    proof: &ChunkProof,
    statement: neutrin0_consensus_types::history_proof::ConsensusStatement,
) -> Result<HistoryProof, ProofError> {
    if statement.chunk != proof.public_inputs
        || statement.chunk.chunk_id != proof.chunk_id
        || neutrin0_prover_chunk::consensus::as_chunk(&statement.chunk).hash() != proof.chunk_hash
        || neutrin0_consensus_types::evidence::commitment(&proof.finality_cert)
            != statement.finality_cert_hash
    {
        return Err(ProofError::PublicInputMismatch);
    }
    Ok(HistoryProof {
        statement: ChunkReceiptStatement {
            statement,
            chunk_prover_address: proof.prover_address,
        },
        receipt: BoundedBytes::new(proof.proof_bytes.clone())
            .map_err(|_| ProofError::MalformedProof)?,
    })
}

impl<DB: Database> Engine<DB> {
    /// Number of complete chunks finalized locally.
    #[must_use]
    pub fn finalized_next_chunk_id(&self) -> u64 {
        self.latest_finalized_chunk_id().map_or(0, |id| {
            id.checked_add(1)
                .expect("finalized chunk count was validated")
        })
    }

    /// Canonical finality boundary, never inferred from peer metadata.
    pub fn canonical_boundary(
        &self,
        count: u64,
    ) -> Result<ConsensusBoundary, FinalizeError<DB::Error>> {
        // The specification's own start is trusted at its count even before
        // a forked node holds anything; nothing below it is this chain's.
        let first = self.chain_spec().first_chunk();
        if count == first {
            return self.trusted_genesis_boundary();
        }
        if count < first || count > self.finalized_next_chunk_id() {
            return Err(ProofError::InvalidWitness.into());
        }
        let boundary = self
            .store()
            .consensus_boundary(count)?
            .ok_or(ProofError::InvalidWitness)?;
        if !boundary.is_well_formed(self.chain_spec()) {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(boundary)
    }

    /// The boundary this specification's History starts from: genesis, or a
    /// hard fork's pinned start.
    pub fn trusted_genesis_boundary(&self) -> Result<ConsensusBoundary, FinalizeError<DB::Error>> {
        Ok(ConsensusBoundary::first(self.chain_spec()))
    }

    /// Pin the active program profile, verified by the configured proof backend.
    /// Called once after the backend derives its trusted keys.
    pub fn set_history_domain(
        &mut self,
        domain: ProofDomain,
    ) -> Result<(), FinalizeError<DB::Error>> {
        // The domain must be exactly this specification's binding and the
        // chunk Guest the specification pins.
        if !domain.is_valid(self.chain_spec()) {
            return Err(ProofError::PublicInputMismatch.into());
        }
        if !domain.programs.is_complete()
            || self
                .programs
                .is_some_and(|programs| programs != domain.programs)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        self.store_mut().set_history_domain(&domain)?;
        self.programs = Some(domain.programs);
        Ok(())
    }

    /// The History proof ending at the canonical boundary `count`: the
    /// retained receipt of chunk `count - 1`. `None` at genesis and once that
    /// receipt has been pruned.
    pub fn history_proof(
        &self,
        count: u64,
    ) -> Result<Option<HistoryProof>, FinalizeError<DB::Error>> {
        let Some(id) = count.checked_sub(1) else {
            return Ok(None);
        };
        let boundary = self.canonical_boundary(count)?;
        let (Some(proof), Some(statement)) = (
            self.store().get_chunk_proof(id)?,
            self.store().chunk_statement(id)?,
        ) else {
            return Ok(None);
        };
        if statement.end != boundary || statement.chain != self.chain_binding() {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(Some(history_proof_of(&proof, statement)?))
    }

    /// The History proof of the latest finalized boundary.
    pub fn latest_history_proof(&self) -> Result<Option<HistoryProof>, FinalizeError<DB::Error>> {
        self.history_proof(self.finalized_next_chunk_id())
    }

    /// The opening that places the boundary at `anchor` chunks under the
    /// history root of the canonical boundary `end`. The specification's
    /// start (genesis or a fork's start) and `end` itself need none, and
    /// nothing below the start belongs to this specification. The opening is
    /// built from the retained record of chunk `anchor`, which commits that
    /// chunk's start boundary, so the boundary itself need not be retained:
    /// the requester compares the commitment with its own trusted boundary.
    /// Pruned nodes open the records they keep for
    /// `history_record_window_chunks` under their latest count; archives open
    /// any.
    pub fn anchor_opening(
        &self,
        anchor: u64,
        end: u64,
    ) -> Result<Option<AnchorOpening>, FinalizeError<DB::Error>> {
        let first = self.chain_spec().first_chunk();
        if anchor < first || anchor > end || end > self.finalized_next_chunk_id() {
            return Err(ProofError::InvalidWitness.into());
        }
        if !neutrin0_consensus_types::history_proof::needs_opening(first, anchor, end) {
            return Ok(None);
        }
        let opening = self.store().historical_opening(anchor, end)?;
        let context = opening.record.evidence_context();
        let end_root = self.canonical_boundary(end)?.history_root;
        if context.chunk_id != anchor
            || opening.path.index != anchor
            || opening.path.count != end
            || !opening.path.verify(
                neutrin0_consensus_types::evidence::commitment(&context),
                end_root,
            )
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(Some(AnchorOpening {
            context,
            path: opening.path,
        }))
    }
}
