//! Durable value-vote reservations: the atomic intent, manifest, lock and
//! compaction write that precedes every local value signature, and the
//! recovery of interrupted reservations.

use alloc::vec::Vec;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{
    FinalityVote, FinalityVoteData, FinalityVotePhase, NilVoteData, ProofManifest,
    QuorumCertificate,
};
use neutrin0_primitives::{BlsPublicKey, Hash};
use neutrin0_storage::{Batch, Column, Database};

use super::{
    SigningProgress, SigningViolation, VoteIntent, VoteWatermark, compact_round_intents,
    intent_key, manifest_key, nil_key, single_signer_bits, vote_key,
};
use crate::{Engine, EngineError, ProposerKey, SignRequest, StoreError};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    /// Reserve an exact vote and attestation before producing either signature.
    pub(crate) fn sign_vote_durable(
        &mut self,
        voter: &ProposerKey,
        data: FinalityVoteData,
        proof_hashes: Vec<Hash>,
        unlock_quorum: Option<QuorumCertificate>,
    ) -> Result<FinalityVote, EngineError<DB::Error>> {
        self.ensure_signable(voter, data.chunk_id)?;
        self.ensure_no_nil_reservation(voter, &data)?;
        let manifests = self.vote_manifests(data.phase, proof_hashes)?;
        let intent = VoteIntent {
            data: data.clone(),
            validator_index: voter.validator_index(),
            proof_acceptance: manifests.first().map(ProofManifest::commitment),
            unlock_quorum,
        };
        let key = vote_key(voter.public_key_bytes(), data.chunk_id);
        let mut watermark = self.load_vote_watermark(voter, data.chunk_id, data.round)?;
        let prior_round = watermark.round;
        let prior_lock = watermark.locked.clone();
        self.validate_vote_unlock(&intent, watermark.locked.as_ref())?;
        advance_vote_watermark(&mut watermark, &intent)?;
        let mut batch = Batch::new();
        stage_round_advance(
            &mut batch,
            voter.public_key_bytes(),
            &data,
            prior_round,
            prior_lock.as_ref(),
        );
        batch.put(Column::SigningJournal, key, borsh::to_vec(&watermark)?);
        batch.put(
            Column::SigningJournal,
            intent_key(voter.public_key_bytes(), &data),
            borsh::to_vec(&intent)?,
        );
        self.stage_vote_manifests(
            &mut batch,
            voter.public_key_bytes(),
            data.chunk_id,
            &manifests,
        )?;
        self.store_mut().write_observed_batch(batch, true)?;

        let vote = self.sign_reserved_value_vote(voter, data, intent, manifests)?;
        // Local publication has capacity reserved from peer artifacts.
        self.retain_signed_artifact(&SignedArtifact::Vote(vote.clone()), true)?;
        Ok(vote)
    }

    /// A value and a nil vote share one signing position: refuse the value
    /// when nil is already reserved there.
    fn ensure_no_nil_reservation(
        &self,
        voter: &ProposerKey,
        data: &FinalityVoteData,
    ) -> Result<(), EngineError<DB::Error>> {
        if self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &nil_key(
                    voter.public_key_bytes(),
                    &NilVoteData {
                        chunk_id: data.chunk_id,
                        round: data.round,
                        phase: data.phase,
                    },
                ),
            )
            .map_err(StoreError::Database)?
            .is_some()
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        Ok(())
    }

    /// The proof manifests a vote in `phase` attests: none for a prevote and
    /// exactly one complete chunk-sized list for a precommit.
    fn vote_manifests(
        &self,
        phase: FinalityVotePhase,
        proof_hashes: Vec<Hash>,
    ) -> Result<Vec<ProofManifest>, EngineError<DB::Error>> {
        match phase {
            FinalityVotePhase::Prevote if proof_hashes.is_empty() => Ok(Vec::new()),
            FinalityVotePhase::Precommit
                if u64::try_from(proof_hashes.len()).ok()
                    == Some(self.chain_spec().consensus.chunk_size) =>
            {
                Ok(vec![ProofManifest { proof_hashes }])
            }
            _ => Err(EngineError::Signing(SigningViolation::Conflict)),
        }
    }

    /// Stage every reserved full proof list, refusing a changed list under an
    /// existing key, then drop the lists no surviving reservation references.
    fn stage_vote_manifests(
        &self,
        batch: &mut Batch,
        identity: &BlsPublicKey,
        chunk_id: u64,
        manifests: &[ProofManifest],
    ) -> Result<(), EngineError<DB::Error>> {
        for manifest in manifests {
            let key = manifest_key(identity, chunk_id, &manifest.commitment());
            let bytes = borsh::to_vec(manifest)?;
            if self
                .store()
                .db()
                .get(Column::SigningJournal, &key)
                .map_err(StoreError::Database)?
                .is_some_and(|prior| prior != bytes)
            {
                return Err(StoreError::Corrupt("reserved proof manifest changed").into());
            }
            batch.put(Column::SigningJournal, key, bytes);
        }
        self.compact_signing_manifests(batch, identity, chunk_id)
    }

    fn sign_reserved_value_vote(
        &self,
        voter: &ProposerKey,
        data: FinalityVoteData,
        intent: VoteIntent,
        manifests: Vec<ProofManifest>,
    ) -> Result<FinalityVote, EngineError<DB::Error>> {
        let mut claim = neutrin0_consensus_types::VoteAttestation {
            validator_index: voter.validator_index(),
            vote_signature: [0; 96],
            vote: data,
            proof_acceptance: intent.proof_acceptance,
            unlock_quorum: intent.unlock_quorum,
            signature: [0; 96],
        };
        let signatures = voter
            .sign(self.consensus_domain(), &SignRequest::Vote(claim.clone()))
            .map_err(EngineError::Signer)?;
        claim.vote_signature = signatures[0];
        claim.signature = signatures[1];
        Ok(FinalityVote {
            aggregation_bits: single_signer_bits(
                self.active_validator_set().len(),
                voter.validator_index(),
            ),
            signature: claim.vote_signature,
            data: claim.vote.clone(),
            attestations: vec![claim],
            proof_manifests: manifests,
        })
    }

    fn validate_vote_unlock(
        &self,
        intent: &VoteIntent,
        locked: Option<&QuorumCertificate>,
    ) -> Result<(), EngineError<DB::Error>> {
        if intent.data.phase == FinalityVotePhase::Prevote && intent.proof_acceptance.is_some() {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        if let Some(unlock) = &intent.unlock_quorum
            && self
                .verify_bft_unlock_quorum(self.active_validator_set(), &intent.data, unlock)
                .is_err()
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        if let Some(lock) = locked
            && !intent.data.same_value(&lock.data)
            && intent
                .unlock_quorum
                .as_ref()
                .is_none_or(|unlock| unlock.data.round <= lock.data.round)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        // Live precommits are emitted only after the current-round prevote QC.
        // Retaining that exact QC in the journal makes a lock survive even if
        // the subsequent session write is interrupted.
        if intent.data.phase == FinalityVotePhase::Precommit
            && intent
                .unlock_quorum
                .as_ref()
                .is_none_or(|unlock| unlock.data.round != intent.data.round)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        Ok(())
    }

    /// Finish interrupted value reservations using their original authenticated
    /// inputs, as read with `progress`.
    pub(crate) fn reserved_local_votes(
        &mut self,
        voter: &ProposerKey,
        progress: &SigningProgress,
    ) -> Result<Vec<FinalityVote>, EngineError<DB::Error>> {
        let mut messages = Vec::new();
        for intent in progress.intents.iter().flatten() {
            let proof_hashes = self
                .reserved_proof_manifest(voter.public_key_bytes(), intent)?
                .map_or_else(Vec::new, |manifest| manifest.proof_hashes);
            messages.push(self.sign_vote_durable(
                voter,
                intent.data.clone(),
                proof_hashes,
                intent.unlock_quorum.clone(),
            )?);
        }
        Ok(messages)
    }

    /// Authenticated journal position, retained lock and value intents of
    /// `voter` for `chunk_id`, read with a single watermark lookup.
    pub(crate) fn reserved_signing_progress(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
    ) -> Result<Option<SigningProgress>, EngineError<DB::Error>> {
        let Some(watermark) = self.read_vote_watermark(
            voter.public_key_bytes(),
            chunk_id,
            "signing lock identity mismatch",
            false,
        )?
        else {
            return Ok(None);
        };
        let prevoted = watermark.prevote.is_some()
            || self
                .reserved_nil_intent(voter, chunk_id, watermark.round, FinalityVotePhase::Prevote)?
                .is_some();
        let precommitted = watermark.precommit.is_some()
            || self
                .reserved_nil_intent(
                    voter,
                    chunk_id,
                    watermark.round,
                    FinalityVotePhase::Precommit,
                )?
                .is_some();
        Ok(Some(SigningProgress {
            round: watermark.round,
            prevoted,
            precommitted,
            locked: watermark.locked,
            intents: [watermark.prevote, watermark.precommit],
        }))
    }

    pub(crate) fn verify_saved_local_vote(
        &self,
        identity: BlsPublicKey,
        vote: &FinalityVote,
    ) -> Result<(), EngineError<DB::Error>> {
        let Some((index, _)) =
            crate::slashing::extract_single_signer(vote, self.active_validator_set().len())
        else {
            return Err(StoreError::Corrupt("saved local vote is not individual").into());
        };
        if self
            .active_validator_set()
            .get(usize::try_from(index).expect("u32 fits usize"))
            .is_none_or(|validator| validator.pubkey != identity)
        {
            return Err(StoreError::Corrupt("saved local vote identity mismatch").into());
        }
        let [claim] = vote.attestations.as_slice() else {
            return Err(StoreError::Corrupt("saved local attestation coverage changed").into());
        };
        let bytes = self
            .store()
            .db()
            .get(Column::SigningJournal, &intent_key(&identity, &vote.data))
            .map_err(StoreError::Database)?
            .ok_or(StoreError::Corrupt("saved local vote reservation missing"))?;
        let intent: VoteIntent = borsh::from_slice(&bytes)?;
        if intent.data != vote.data
            || intent.validator_index != index
            || intent.proof_acceptance != claim.proof_acceptance
            || intent.unlock_quorum != claim.unlock_quorum
        {
            return Err(StoreError::Corrupt("saved local vote reservation mismatch").into());
        }
        let expected: Vec<_> = self
            .reserved_proof_manifest(&identity, &intent)?
            .into_iter()
            .collect();
        if vote.proof_manifests != expected {
            return Err(StoreError::Corrupt("saved local proof manifest mismatch").into());
        }
        Ok(())
    }
}

/// Move `watermark` to the intent's round and record the intent in its phase
/// slot; a differing intent already reserved there is a conflict, and a
/// precommit's unlock quorum becomes the retained lock.
fn advance_vote_watermark<E>(
    watermark: &mut VoteWatermark,
    intent: &VoteIntent,
) -> Result<(), EngineError<E>> {
    let data = &intent.data;
    watermark
        .advance(data.round)
        .map_err(EngineError::Signing)?;
    let entry = match data.phase {
        FinalityVotePhase::Prevote => &mut watermark.prevote,
        FinalityVotePhase::Precommit => &mut watermark.precommit,
    };
    if entry.as_ref().is_some_and(|prior| *prior != *intent) {
        return Err(EngineError::Signing(SigningViolation::Conflict));
    }
    *entry = Some(intent.clone());
    if data.phase == FinalityVotePhase::Precommit {
        watermark.locked.clone_from(&intent.unlock_quorum);
    }
    Ok(())
}

/// Stage the removal of the positions the round advance renders unsignable,
/// including the prior lock's original precommit once a later precommit
/// replaces that lock.
fn stage_round_advance(
    batch: &mut Batch,
    identity: &BlsPublicKey,
    data: &FinalityVoteData,
    prior_round: u32,
    prior_lock: Option<&QuorumCertificate>,
) {
    compact_round_intents(
        batch,
        identity,
        data.chunk_id,
        prior_round,
        data.round,
        prior_lock,
    );
    if data.phase == FinalityVotePhase::Precommit
        && let Some(lock) = prior_lock.filter(|lock| lock.data.round < data.round)
    {
        let locked_precommit = FinalityVoteData {
            phase: FinalityVotePhase::Precommit,
            ..lock.data.clone()
        };
        batch.delete(
            Column::SigningJournal,
            intent_key(identity, &locked_precommit),
        );
    }
}
