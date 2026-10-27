//! Durable nil-vote reservations, in the same anti-equivocation position as
//! a value vote of that round and phase.

use alloc::vec::Vec;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{
    FinalityVoteData, FinalityVotePhase, NilVote, NilVoteAttestation, NilVoteData,
};
use neutrin0_primitives::BlsPublicKey;
use neutrin0_storage::{Batch, Column, Database};

use super::{
    NilIntent, SigningViolation, compact_round_intents, intent_key, nil_key, single_signer_bits,
    vote_key,
};
use crate::{Engine, EngineError, ProposerKey, SignRequest, StoreError};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    /// Reserve explicit nil in the same anti-equivocation position as a value.
    /// Nil precommits preserve the durable lock from every earlier value.
    pub(crate) fn sign_nil_vote_durable(
        &mut self,
        voter: &ProposerKey,
        data: NilVoteData,
    ) -> Result<NilVote, EngineError<DB::Error>> {
        self.ensure_signable(voter, data.chunk_id)?;
        let value_data = FinalityVoteData {
            chunk_id: data.chunk_id,
            round: data.round,
            phase: data.phase,
            chunk_hash: [0; 32],
            selection: [0; 32],
        };
        if self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &intent_key(voter.public_key_bytes(), &value_data),
            )
            .map_err(StoreError::Database)?
            .is_some()
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        let key = vote_key(voter.public_key_bytes(), data.chunk_id);
        let mut watermark = self.load_vote_watermark(voter, data.chunk_id, data.round)?;
        let prior_round = watermark.round;
        watermark
            .advance(data.round)
            .map_err(EngineError::Signing)?;
        let intent = NilIntent {
            spec: self.chain_spec_hash(),
            identity: *voter.public_key_bytes(),
            data: data.clone(),
            validator_index: voter.validator_index(),
        };
        let nil_key = nil_key(voter.public_key_bytes(), &data);
        let bytes = borsh::to_vec(&intent)?;
        if self
            .store()
            .db()
            .get(Column::SigningJournal, &nil_key)
            .map_err(StoreError::Database)?
            .is_some_and(|prior| prior != bytes)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        let mut batch = Batch::new();
        compact_round_intents(
            &mut batch,
            voter.public_key_bytes(),
            data.chunk_id,
            prior_round,
            data.round,
            watermark.locked.as_ref(),
        );
        batch.put(Column::SigningJournal, key, borsh::to_vec(&watermark)?);
        batch.put(Column::SigningJournal, nil_key, bytes);
        self.compact_signing_manifests(&mut batch, voter.public_key_bytes(), data.chunk_id)?;
        self.store_mut().write_observed_batch(batch, true)?;
        let mut claim = NilVoteAttestation {
            validator_index: voter.validator_index(),
            vote: data.clone(),
            vote_signature: [0; 96],
            signature: [0; 96],
        };
        let signatures = voter
            .sign(
                self.consensus_domain(),
                &SignRequest::NilVote(claim.clone()),
            )
            .map_err(EngineError::Signer)?;
        claim.vote_signature = signatures[0];
        claim.signature = signatures[1];
        let vote = NilVote {
            data,
            aggregation_bits: single_signer_bits(
                self.active_validator_set().len(),
                voter.validator_index(),
            ),
            signature: claim.vote_signature,
            attestations: vec![claim],
        };
        self.retain_signed_artifact(&SignedArtifact::NilVote(vote.clone()), true)?;
        Ok(vote)
    }

    pub(super) fn reserved_nil_intent(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
        phase: FinalityVotePhase,
    ) -> Result<Option<NilIntent>, EngineError<DB::Error>> {
        let data = NilVoteData {
            chunk_id,
            round,
            phase,
        };
        self.store()
            .db()
            .get(
                Column::SigningJournal,
                &nil_key(voter.public_key_bytes(), &data),
            )
            .map_err(StoreError::Database)?
            .map(|bytes| {
                let intent: NilIntent = borsh::from_slice(&bytes)?;
                if intent.spec != self.chain_spec_hash()
                    || intent.identity != *voter.public_key_bytes()
                    || intent.data != data
                    || intent.validator_index != voter.validator_index()
                {
                    return Err(StoreError::Corrupt("nil signing reservation changed").into());
                }
                Ok(intent)
            })
            .transpose()
    }

    pub(crate) fn reserved_local_nil_votes(
        &mut self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Vec<NilVote>, EngineError<DB::Error>> {
        let mut recovered = Vec::new();
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            if let Some(intent) = self.reserved_nil_intent(voter, chunk_id, round, phase)? {
                recovered.push(self.sign_nil_vote_durable(voter, intent.data)?);
            }
        }
        Ok(recovered)
    }

    pub(crate) fn verify_saved_nil_vote(
        &self,
        identity: BlsPublicKey,
        vote: &NilVote,
    ) -> Result<(), EngineError<DB::Error>> {
        let [claim] = vote.attestations.as_slice() else {
            return Err(StoreError::Corrupt("saved local nil coverage changed").into());
        };
        if self
            .active_validator_set()
            .get(usize::try_from(claim.validator_index).expect("u32 fits usize"))
            .is_none_or(|validator| validator.pubkey != identity)
        {
            return Err(StoreError::Corrupt("saved nil identity mismatch").into());
        }
        let bytes = self
            .store()
            .db()
            .get(Column::SigningJournal, &nil_key(&identity, &vote.data))
            .map_err(StoreError::Database)?
            .ok_or(StoreError::Corrupt("saved nil reservation missing"))?;
        let intent: NilIntent = borsh::from_slice(&bytes)?;
        if intent.spec != self.chain_spec_hash()
            || intent.identity != identity
            || intent.data != vote.data
            || intent.validator_index != claim.validator_index
        {
            return Err(StoreError::Corrupt("saved nil reservation mismatch").into());
        }
        Ok(())
    }
}
