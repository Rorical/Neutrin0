//! The proposer slot watermark reserved before every header signature.

use neutrin0_consensus_types::Header;
use neutrin0_primitives::BlsSignature;
use neutrin0_storage::{Batch, Column, Database};

use super::{ProposalWatermark, SigningViolation, proposal_key};
use crate::{Engine, EngineError, ProposerKey, SignRequest, StoreError};

impl<DB: Database> Engine<DB> {
    /// Reserve the proposer slot and complete header hash before signing.
    pub(crate) fn sign_proposal_durable(
        &mut self,
        voter: &ProposerKey,
        header: &Header,
    ) -> Result<BlsSignature, EngineError<DB::Error>> {
        let (slot, hash) = (header.slot, header.hash());
        if self.signing_quiet() {
            return Err(EngineError::Signing(SigningViolation::Quiet));
        }
        if !self.local_signing_enabled() {
            return Err(EngineError::Signing(SigningViolation::Paused));
        }
        if !self
            .production_committee()
            .0
            .get(voter.validator_index() as usize)
            .is_some_and(|validator| {
                validator.pubkey == *voter.public_key_bytes() && validator.effective_stake > 0
            })
        {
            return Err(EngineError::Signing(SigningViolation::KeyNotActive));
        }
        let key = proposal_key(voter.public_key_bytes());
        if let Some(bytes) = self
            .store()
            .db()
            .get(Column::SigningJournal, &key)
            .map_err(StoreError::Database)?
        {
            let prior: ProposalWatermark = borsh::from_slice(&bytes)?;
            if prior.spec != self.chain_spec_hash() || prior.identity != *voter.public_key_bytes() {
                return Err(StoreError::Corrupt("proposal journal identity mismatch").into());
            }
            if slot < prior.slot {
                return Err(EngineError::Signing(SigningViolation::Regression));
            }
            if slot == prior.slot && hash != prior.hash {
                return Err(EngineError::Signing(SigningViolation::Conflict));
            }
        }
        let mut batch = Batch::new();
        batch.put(
            Column::SigningJournal,
            key,
            borsh::to_vec(&ProposalWatermark {
                spec: self.chain_spec_hash(),
                identity: *voter.public_key_bytes(),
                slot,
                hash,
            })?,
        );
        self.store_mut().write_observed_batch(batch, true)?;
        let signatures = voter
            .sign(
                self.consensus_domain(),
                &SignRequest::Header(header.clone()),
            )
            .map_err(EngineError::Signer)?;
        Ok(signatures[0])
    }
}
