//! Detection of signed acceptance of locally rejected block proofs.

extern crate alloc;

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    BlockProof, FinalityVote, IndexedVote, ProofAcceptanceOpening, ProofManifestIndex,
    SlashingEvidence, VoteAttestation,
};
use neutrin0_primitives::Validator;
use neutrin0_storage::Database;

use super::Engine;
use crate::slashing::{self, SlashingError};

impl<DB: Database> Engine<DB> {
    /// Detect proof acceptance violations for every individually attested aggregate signer.
    pub fn observe_vote_for_invalid_proof_signing(
        &self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let mut evidence = alloc::vec::Vec::new();
        for individual in self.attributable_votes(vote)? {
            evidence.extend(self.observe_individual_for_invalid_proof_signing(&individual)?);
        }
        Ok(evidence)
    }

    /// Detect [`SlashingEvidence::InvalidProofSigning`] from an
    /// inbound finality vote.
    ///
    /// Returns evidence for every block at a covered height of the vote's
    /// chunk, on any branch, whose exact proof envelope the signer explicitly
    /// attested to and the local engine rejected at gossip-import
    /// time (see [`crate::Engine::import_block_proof`]'s rejected-
    /// proof cache). The signer's per-validator signature is
    /// re-verified before evidence is emitted so a malicious peer
    /// cannot pollute the slashing pool with claims attributed to a
    /// validator who did not actually sign.
    ///
    /// This helper consumes individual votes recovered by the public entry
    /// point from an aggregate's mandatory per-signer attestations.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SlashingError`] variant when the
    /// signature on the underlying vote fails to verify against
    /// the active set.
    fn observe_individual_for_invalid_proof_signing(
        &self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let validators = self.accountability_validators(vote.data.chunk_id)?;
        let active_set_len = validators.len();
        let Some((signer, indexed)) = slashing::extract_single_signer(vote, active_set_len) else {
            return Ok(alloc::vec::Vec::new());
        };
        slashing::verify_indexed_vote_signature_using(
            signer,
            &indexed,
            &validators,
            self.consensus_domain(),
            &mut *self.bls_verifier.borrow_mut(),
        )?;

        // Explicit proof-acceptance detection only applies to precommit phase
        // (signing off on a chunk's finalisability). Prevotes are
        // expressions of "ready to lock in", not declarations of
        // proof acceptance, so they are not slashable through this
        // path.
        if !matches!(
            indexed.data.phase,
            neutrin0_consensus_types::FinalityVotePhase::Precommit,
        ) {
            return Ok(alloc::vec::Vec::new());
        }

        // chunk_id covers heights [chunk_id*chunk_size + 1, (chunk_id+1)*chunk_size].
        let Some((start, end)) = self.chunk_heights(indexed.data.chunk_id) else {
            return Ok(alloc::vec::Vec::new());
        };

        // The signer accepted exact envelope hashes, not the local canonical
        // branch: a rejected envelope for a sibling block at a covered height
        // is just as attributable, so consult every cached rejection there.
        let mut evidence = alloc::vec::Vec::new();
        let manifests = neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
            .filter(|index| index.covers_exact(&vote.attestations))
            .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        for (rejected_proof, reason) in self.rejected_proofs.within_heights(start, end) {
            let Some(offset) = rejected_proof.height.checked_sub(start) else {
                continue;
            };
            let Some((attestation, proof_opening)) = self.attested_rejection(
                vote,
                &manifests,
                (signer, &indexed, &validators),
                rejected_proof,
                offset,
            ) else {
                continue;
            };
            evidence.push(SlashingEvidence::InvalidProofSigning {
                validator_index: signer,
                vote: indexed.clone(),
                attestation: attestation.clone(),
                rejected_proof: rejected_proof.clone(),
                proof_opening,
                reason: *reason,
            });
        }
        Ok(evidence)
    }

    /// The signer's attestation that explicitly accepted `rejected_proof` at
    /// `offset` of its chunk, with the manifest opening proving it, when its
    /// vote attestation and proof acceptance both verify.
    fn attested_rejection<'a>(
        &self,
        vote: &'a FinalityVote,
        manifests: &ProofManifestIndex<'_>,
        (signer, indexed, validators): (u32, &IndexedVote, &[Validator]),
        rejected_proof: &BlockProof,
        offset: u64,
    ) -> Option<(&'a VoteAttestation, ProofAcceptanceOpening)> {
        let rejected_hash = commitment(rejected_proof);
        vote.attestations.iter().find_map(|attestation| {
            let manifest = manifests.get(&attestation.proof_acceptance?)?;
            if manifest.proof_hashes.get(usize::try_from(offset).ok()?) != Some(&rejected_hash) {
                return None;
            }
            let opening = manifest.opening(offset)?;
            (slashing::verify_vote_attestation_using(
                attestation,
                signer,
                &indexed.data,
                validators,
                self.consensus_domain(),
                &mut *self.bls_verifier.borrow_mut(),
            )
            .is_ok()
                && slashing::verify_proof_acceptance(
                    attestation,
                    rejected_proof,
                    &opening,
                    self.chunk_size(),
                )
                .is_ok())
            .then_some((attestation, opening))
        })
    }
}
