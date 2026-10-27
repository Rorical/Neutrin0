//! The per-identity, per-chunk vote watermark: reading and revalidating it,
//! the signability checks every reservation starts with, and journal expiry
//! below local finality.

use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase};
use neutrin0_primitives::BlsPublicKey;
use neutrin0_storage::{Batch, Column, Database};

use super::{
    CHUNK_KEY_LEN, IDENTITY_KEY_LEN, LAST_CHUNK_TAG, PROPOSER_WATERMARK_TAG, SigningViolation,
    VOTE_INTENT_TAG, VOTE_WATERMARK_TAG, VoteIntent, VoteWatermark, intent_key, vote_key,
};
use crate::{Engine, EngineError, ProposerKey, StoreError};

impl<DB: Database> Engine<DB> {
    fn validate_vote_watermark(
        &self,
        watermark: &VoteWatermark,
    ) -> Result<(), EngineError<DB::Error>> {
        if watermark.spec != self.chain_spec_hash() {
            return Err(StoreError::Corrupt("invalid signing watermark context").into());
        }
        for (phase, intent) in [
            (FinalityVotePhase::Prevote, &watermark.prevote),
            (FinalityVotePhase::Precommit, &watermark.precommit),
        ] {
            let Some(intent) = intent else {
                continue;
            };
            if intent.data.chunk_id != watermark.chunk_id
                || intent.data.round != watermark.round
                || intent.data.phase != phase
            {
                return Err(StoreError::Corrupt("signing watermark intent target mismatch").into());
            }
            let bytes = self
                .store()
                .db()
                .get(
                    Column::SigningJournal,
                    &intent_key(&watermark.identity, &intent.data),
                )
                .map_err(StoreError::Database)?
                .ok_or(StoreError::Corrupt("signing watermark intent missing"))?;
            if borsh::from_slice::<VoteIntent>(&bytes)? != *intent {
                return Err(StoreError::Corrupt("signing watermark intent changed").into());
            }
            if (phase == FinalityVotePhase::Precommit) != intent.proof_acceptance.is_some() {
                return Err(StoreError::Corrupt("signing watermark proof phase mismatch").into());
            }
            let _ = self.reserved_proof_manifest(&watermark.identity, intent)?;
        }
        if let Some(lock) = &watermark.locked {
            let precommit = FinalityVoteData {
                phase: FinalityVotePhase::Precommit,
                ..lock.data.clone()
            };
            let bytes = self
                .store()
                .db()
                .get(
                    Column::SigningJournal,
                    &intent_key(&watermark.identity, &precommit),
                )
                .map_err(StoreError::Database)?
                .ok_or(StoreError::Corrupt("journal lock has no signed precommit"))?;
            let intent: VoteIntent = borsh::from_slice(&bytes)?;
            if intent.proof_acceptance.is_none() {
                return Err(StoreError::Corrupt("journal lock proof manifest missing").into());
            }
            let _ = self.reserved_proof_manifest(&watermark.identity, &intent)?;
            if intent.data != precommit
                || intent.unlock_quorum.as_ref() != Some(lock)
                || lock.data.round > watermark.round
                || self
                    .verify_bft_unlock_quorum(self.active_validator_set(), &precommit, lock)
                    .is_err()
            {
                return Err(StoreError::Corrupt("invalid durable signing lock").into());
            }
        }
        if watermark
            .precommit
            .as_ref()
            .is_some_and(|intent| intent.unlock_quorum != watermark.locked)
        {
            return Err(StoreError::Corrupt("journal precommit lock mismatch").into());
        }
        Ok(())
    }

    /// Read and revalidate the vote watermark of `identity` for `chunk_id`.
    /// A watermark bound to another identity or chunk, or with `bind_spec` to
    /// another specification, fails with the caller's `mismatch` diagnostic.
    pub(super) fn read_vote_watermark(
        &self,
        identity: &BlsPublicKey,
        chunk_id: u64,
        mismatch: &'static str,
        bind_spec: bool,
    ) -> Result<Option<VoteWatermark>, EngineError<DB::Error>> {
        let Some(bytes) = self
            .store()
            .db()
            .get(Column::SigningJournal, &vote_key(identity, chunk_id))
            .map_err(StoreError::Database)?
        else {
            return Ok(None);
        };
        let watermark: VoteWatermark = borsh::from_slice(&bytes)?;
        if (bind_spec && watermark.spec != self.chain_spec_hash())
            || watermark.identity != *identity
            || watermark.chunk_id != chunk_id
        {
            return Err(StoreError::Corrupt(mismatch).into());
        }
        self.validate_vote_watermark(&watermark)?;
        Ok(Some(watermark))
    }

    fn validate_signing_key(&self, voter: &ProposerKey) -> Result<(), EngineError<DB::Error>> {
        if self.signing_quiet() {
            return Err(EngineError::Signing(SigningViolation::Quiet));
        }
        if !self.local_signing_enabled() {
            return Err(EngineError::Signing(SigningViolation::Paused));
        }
        let index = usize::try_from(voter.validator_index()).expect("u32 fits usize");
        if !self
            .active_validator_set()
            .get(index)
            .is_some_and(|validator| {
                validator.pubkey == *voter.public_key_bytes() && validator.effective_stake > 0
            })
        {
            return Err(EngineError::Signing(SigningViolation::KeyNotActive));
        }
        Ok(())
    }

    /// Refuse inactive signing keys and chunks already covered by local finality.
    pub(super) fn ensure_signable(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
    ) -> Result<(), EngineError<DB::Error>> {
        self.validate_signing_key(voter)?;
        // Chunks before a hard fork verify under a predecessor's domain; this
        // specification never signs them (design 20).
        if chunk_id < self.chain_spec().first_chunk() {
            return Err(EngineError::Signing(SigningViolation::PriorDomain));
        }
        if !self.proves_chunk(chunk_id)? {
            return Err(EngineError::Signing(SigningViolation::Halted));
        }
        if chunk_id < self.signing_finalized_floor()? {
            return Err(EngineError::Signing(SigningViolation::FinalizedChunk));
        }
        Ok(())
    }

    pub(super) fn load_vote_watermark(
        &self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<VoteWatermark, EngineError<DB::Error>> {
        let identity = voter.public_key_bytes();
        let saved = self.read_vote_watermark(
            identity,
            chunk_id,
            "signing journal identity mismatch",
            false,
        )?;
        Ok(saved.unwrap_or_else(|| VoteWatermark {
            spec: self.chain_spec_hash(),
            identity: *identity,
            chunk_id,
            round,
            prevote: None,
            precommit: None,
            locked: None,
        }))
    }

    pub(crate) fn signing_round_for(
        &self,
        identity: &BlsPublicKey,
        chunk_id: u64,
    ) -> Result<Option<u32>, EngineError<DB::Error>> {
        Ok(self
            .read_vote_watermark(
                identity,
                chunk_id,
                "signing watermark identity mismatch",
                true,
            )?
            .map(|watermark| watermark.round))
    }

    /// Finality itself forbids old signing, so completed journals can be removed
    /// while retaining proposer slot watermarks and every unfinalized reservation.
    pub(crate) fn expired_signing_entries(
        &self,
        batch: &mut Batch,
    ) -> Result<(), EngineError<DB::Error>> {
        let floor = self.signing_finalized_floor()?;
        for (key, _) in self
            .store()
            .db()
            .iter_column(Column::BftSessions)
            .map_err(StoreError::Database)?
        {
            let id = u64::from_be_bytes(
                key.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invalid saved session key"))?,
            );
            if id < floor {
                batch.delete(Column::BftSessions, key);
            }
        }
        for (key, _) in self
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .map_err(StoreError::Database)?
        {
            if key.first() == Some(&PROPOSER_WATERMARK_TAG) {
                continue;
            }
            if key.len() < CHUNK_KEY_LEN
                || !matches!(
                    key[0],
                    VOTE_WATERMARK_TAG | VOTE_INTENT_TAG..=LAST_CHUNK_TAG
                )
            {
                return Err(StoreError::Corrupt("invalid signing journal key").into());
            }
            let id = u64::from_be_bytes(
                key[IDENTITY_KEY_LEN..CHUNK_KEY_LEN]
                    .try_into()
                    .expect("eight bytes"),
            );
            if id < floor {
                batch.delete(Column::SigningJournal, key);
            }
        }
        Ok(())
    }

    pub(super) fn signing_finalized_floor(&self) -> Result<u64, EngineError<DB::Error>> {
        let persisted = self
            .store()
            .get_latest_finalized_chunk_id()?
            .map(|id| {
                id.checked_add(1)
                    .ok_or(StoreError::Corrupt("signing finality floor overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        Ok(persisted.max(self.finalized_next_chunk_id()))
    }
}
