//! Durable leader-proposal and round-change reservations: the exact unsigned
//! carrier is retained with its signing message before the key is touched.

use alloc::boxed::Box;
use alloc::vec::Vec;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{BftProposal, RoundChange};
use neutrin0_primitives::{BlsPublicKey, BlsSignature};
use neutrin0_storage::{Batch, Column, Database};

use super::{
    CHAIN_ID_OFFSET, DOMAIN_PREFIX_LEN, MessageCarrier, MessageIntent, MessageWatermark,
    PROPOSAL_MESSAGE_TAG, ROUND_CHANGE_MESSAGE_TAG, SPEC_HASH_OFFSET, SigningViolation,
    message_watermark_key, round_message_key,
};
use crate::{Engine, EngineError, ProposerKey, SignRequest, StoreError};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    fn reserve_round_message(
        &mut self,
        voter: &ProposerKey,
        tag: u8,
        chunk_id: u64,
        round: u32,
        message: &[u8],
        carrier: MessageCarrier,
    ) -> Result<BlsSignature, EngineError<DB::Error>> {
        self.ensure_signable(voter, chunk_id)?;
        if self
            .signing_round_for(voter.public_key_bytes(), chunk_id)?
            .is_some_and(|signed_round| signed_round > round)
        {
            return Err(EngineError::Signing(SigningViolation::Regression));
        }
        let key = round_message_key(tag, voter.public_key_bytes(), chunk_id, round);
        let intent = MessageIntent {
            spec: self.chain_spec_hash(),
            identity: *voter.public_key_bytes(),
            message: message.to_vec(),
            carrier,
        };
        let bytes = borsh::to_vec(&intent)?;
        if self
            .store()
            .db()
            .get(Column::SigningJournal, &key)
            .map_err(StoreError::Database)?
            .is_some_and(|prior| prior != bytes)
        {
            return Err(EngineError::Signing(SigningViolation::Conflict));
        }
        let mut batch = Batch::new();
        self.compact_message_intents(&mut batch, tag, voter.public_key_bytes(), chunk_id, round)?;
        batch.put(Column::SigningJournal, key, bytes);
        self.store_mut().write_observed_batch(batch, true)?;
        let request = match intent.carrier {
            MessageCarrier::Proposal(proposal) => SignRequest::Proposal(proposal),
            MessageCarrier::RoundChange(report) => SignRequest::RoundChange(*report),
        };
        let signatures = voter
            .sign(self.consensus_domain(), &request)
            .map_err(EngineError::Signer)?;
        Ok(signatures[0])
    }

    /// Message-only rounds can be abandoned before reserving a vote. Track each
    /// message kind independently so those positions remain bounded as well.
    fn compact_message_intents(
        &self,
        batch: &mut Batch,
        tag: u8,
        identity: &BlsPublicKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<(), EngineError<DB::Error>> {
        let key = message_watermark_key(tag, identity, chunk_id);
        if let Some(bytes) = self
            .store()
            .db()
            .get(Column::SigningJournal, &key)
            .map_err(StoreError::Database)?
        {
            let prior: MessageWatermark = borsh::from_slice(&bytes)?;
            if prior.spec != self.chain_spec_hash()
                || prior.identity != *identity
                || prior.chunk_id != chunk_id
            {
                return Err(
                    StoreError::Corrupt("message signing watermark identity mismatch").into(),
                );
            }
            if round < prior.round {
                return Err(EngineError::Signing(SigningViolation::Regression));
            }
            if round > prior.round {
                batch.delete(
                    Column::SigningJournal,
                    round_message_key(tag, identity, chunk_id, prior.round),
                );
            }
        }
        batch.put(
            Column::SigningJournal,
            key,
            borsh::to_vec(&MessageWatermark {
                spec: self.chain_spec_hash(),
                identity: *identity,
                chunk_id,
                round,
            })?,
        );
        Ok(())
    }

    fn reserved_round_intent(
        &self,
        tag: u8,
        identity: &BlsPublicKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Option<MessageIntent>, EngineError<DB::Error>> {
        self.store()
            .db()
            .get(
                Column::SigningJournal,
                &round_message_key(tag, identity, chunk_id, round),
            )
            .map_err(StoreError::Database)?
            .map(|bytes| {
                let intent: MessageIntent = borsh::from_slice(&bytes)?;
                if intent.spec != self.chain_spec_hash()
                    || intent.identity != *identity
                    || intent.message.len() < DOMAIN_PREFIX_LEN
                    || intent.message[CHAIN_ID_OFFSET..SPEC_HASH_OFFSET]
                        != self.chain_spec().chain_id.to_le_bytes()
                    || intent.message[SPEC_HASH_OFFSET..DOMAIN_PREFIX_LEN] != self.chain_spec_hash()
                {
                    return Err(StoreError::Corrupt("round message reservation changed").into());
                }
                let valid_carrier = match &intent.carrier {
                    MessageCarrier::Proposal(proposal) => {
                        tag == PROPOSAL_MESSAGE_TAG
                            && proposal.chunk.chunk_id == chunk_id
                            && proposal.round == round
                            && proposal.signature == [0; 96]
                            && proposal.signing_message(self.consensus_domain()) == intent.message
                    }
                    MessageCarrier::RoundChange(report) => {
                        tag == ROUND_CHANGE_MESSAGE_TAG
                            && report.chunk_id == chunk_id
                            && report.round == round
                            && report.signature == [0; 96]
                            && report.signing_message(self.consensus_domain()) == intent.message
                    }
                };
                if !valid_carrier {
                    return Err(StoreError::Corrupt("round signing carrier changed").into());
                }
                Ok(intent)
            })
            .transpose()
    }

    fn reserved_round_message(
        &self,
        tag: u8,
        identity: &BlsPublicKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Option<Vec<u8>>, EngineError<DB::Error>> {
        Ok(self
            .reserved_round_intent(tag, identity, chunk_id, round)?
            .map(|intent| intent.message))
    }

    pub(crate) fn reserved_bft_proposal(
        &mut self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Option<BftProposal>, EngineError<DB::Error>> {
        let Some(intent) = self.reserved_round_intent(
            PROPOSAL_MESSAGE_TAG,
            voter.public_key_bytes(),
            chunk_id,
            round,
        )?
        else {
            return Ok(None);
        };
        let MessageCarrier::Proposal(proposal) = intent.carrier else {
            return Err(StoreError::Corrupt("reserved proposal carrier kind").into());
        };
        let proposal = *proposal;
        if proposal.chunk.chunk_id != chunk_id
            || proposal.round != round
            || proposal.proposer_index != voter.validator_index()
            || proposal.signing_message(self.consensus_domain()) != intent.message
        {
            return Err(StoreError::Corrupt("reserved proposal tuple changed").into());
        }
        self.sign_bft_proposal_durable(voter, proposal).map(Some)
    }

    pub(crate) fn reserved_round_change(
        &mut self,
        voter: &ProposerKey,
        chunk_id: u64,
        round: u32,
    ) -> Result<Option<RoundChange>, EngineError<DB::Error>> {
        let Some(intent) = self.reserved_round_intent(
            ROUND_CHANGE_MESSAGE_TAG,
            voter.public_key_bytes(),
            chunk_id,
            round,
        )?
        else {
            return Ok(None);
        };
        let MessageCarrier::RoundChange(report) = intent.carrier else {
            return Err(StoreError::Corrupt("reserved round report carrier kind").into());
        };
        let report = *report;
        if report.chunk_id != chunk_id
            || report.round != round
            || report.validator_index != voter.validator_index()
            || report.signing_message(self.consensus_domain()) != intent.message
        {
            return Err(StoreError::Corrupt("reserved round report tuple changed").into());
        }
        self.sign_round_change_durable(voter, report).map(Some)
    }

    pub(crate) fn verify_saved_round_report(
        &self,
        identity: BlsPublicKey,
        report: &RoundChange,
    ) -> Result<(), EngineError<DB::Error>> {
        let reserved = self.reserved_round_message(
            ROUND_CHANGE_MESSAGE_TAG,
            &identity,
            report.chunk_id,
            report.round,
        )?;
        if reserved != Some(report.signing_message(self.consensus_domain())) {
            return Err(StoreError::Corrupt("saved round report reservation missing").into());
        }
        Ok(())
    }

    pub(crate) fn sign_bft_proposal_durable(
        &mut self,
        voter: &ProposerKey,
        mut proposal: BftProposal,
    ) -> Result<BftProposal, EngineError<DB::Error>> {
        proposal.signature = [0; 96];
        proposal.signature = self.reserve_round_message(
            voter,
            PROPOSAL_MESSAGE_TAG,
            proposal.chunk.chunk_id,
            proposal.round,
            &proposal.signing_message(self.consensus_domain()),
            MessageCarrier::Proposal(Box::new(proposal.clone())),
        )?;
        self.retain_signed_artifact(&SignedArtifact::Proposal(Box::new(proposal.clone())), true)?;
        Ok(proposal)
    }

    pub(crate) fn sign_round_change_durable(
        &mut self,
        voter: &ProposerKey,
        mut report: RoundChange,
    ) -> Result<RoundChange, EngineError<DB::Error>> {
        report.signature = [0; 96];
        report.signature = self.reserve_round_message(
            voter,
            ROUND_CHANGE_MESSAGE_TAG,
            report.chunk_id,
            report.round,
            &report.signing_message(self.consensus_domain()),
            MessageCarrier::RoundChange(Box::new(report.clone())),
        )?;
        self.retain_signed_artifact(&SignedArtifact::RoundChange(report.clone()), true)?;
        Ok(report)
    }
}
