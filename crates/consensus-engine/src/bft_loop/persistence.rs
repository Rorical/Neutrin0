//! Authenticated restart reconstruction of unfinalized BFT sessions.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_chunk_bft::Pacemaker;
use neutrin0_consensus_types::{
    BftProposal, Chunk, FinalityVote, FinalityVotePhase, NilVote, PaymentSelection, ProofManifest,
    ProofManifestIndex, QuorumCertificate, RoundChange, RoundChangeCertificate,
};
use neutrin0_primitives::{BlsPublicKey, Hash, Validator};
use neutrin0_storage::{Batch, Column, Database};

use super::{BftLoopError, BftSession};
use crate::{Engine, EngineError, StoreError};

extern crate alloc;

mod restore;
mod resume;

#[cfg(test)]
mod tests;

const MAX_SESSION_BYTES: usize = 16 * 1024 * 1024;

/// One value or nil signature per phase: prevote and precommit.
const MAX_LOCAL_PHASE_VOTES: usize = 2;

/// Owned durable session, used to decode. [`SavedSessionRef`] writes the same
/// fields in the same order; borsh encodes `&T` as `T` and `&[T]` as `Vec<T>`.
#[derive(BorshSerialize, BorshDeserialize)]
struct SavedSession {
    spec: Hash,
    chunk: Chunk,
    validators: Vec<Validator>,
    validator_root: Hash,
    proof_hashes: Vec<Hash>,
    round: u32,
    round_started_at_secs: u64,
    prevote: Option<FinalityVote>,
    precommit: Option<FinalityVote>,
    local_identity: Option<BlsPublicKey>,
    local_votes: Vec<FinalityVote>,
    highest_lock: Option<QuorumCertificate>,
    prevote_justification: Option<QuorumCertificate>,
    pacemaker: Pacemaker,
    proposal: Option<BftProposal>,
    valid_value: Option<(Chunk, PaymentSelection, QuorumCertificate)>,
    candidates: BTreeMap<Hash, Chunk>,
    selections: BTreeMap<Hash, PaymentSelection>,
    local_nil_votes: Vec<NilVote>,
    nil_prevote: Option<NilVote>,
    nil_precommit: Option<NilVote>,
    round_certificate: Option<RoundChangeCertificate>,
    local_round_report: Option<RoundChange>,
    /// Value votes held before the round's proposal (design 08).
    pending_votes: Vec<FinalityVote>,
}

/// Borrowed encoding of [`SavedSession`]; field order and wire types must match.
#[derive(BorshSerialize)]
struct SavedSessionRef<'a> {
    spec: Hash,
    chunk: &'a Chunk,
    validators: &'a [Validator],
    validator_root: Hash,
    proof_hashes: &'a [Hash],
    round: u32,
    round_started_at_secs: u64,
    prevote: Option<FinalityVote>,
    precommit: Option<FinalityVote>,
    local_identity: Option<BlsPublicKey>,
    local_votes: &'a [FinalityVote],
    highest_lock: Option<&'a QuorumCertificate>,
    prevote_justification: Option<&'a QuorumCertificate>,
    pacemaker: &'a Pacemaker,
    proposal: Option<&'a BftProposal>,
    valid_value: Option<&'a (Chunk, PaymentSelection, QuorumCertificate)>,
    candidates: &'a BTreeMap<Hash, Chunk>,
    selections: &'a BTreeMap<Hash, PaymentSelection>,
    local_nil_votes: &'a [NilVote],
    nil_prevote: Option<NilVote>,
    nil_precommit: Option<NilVote>,
    round_certificate: Option<&'a RoundChangeCertificate>,
    local_round_report: Option<&'a RoundChange>,
    pending_votes: Vec<FinalityVote>,
}

/// Local signatures must recover the same full list, not only a dictionary
/// with a matching claimed root. Peer signers may accept other valid encodings.
fn local_manifest_matches(vote: &FinalityVote, proof_hashes: &[Hash]) -> bool {
    let expected = ProofManifest {
        proof_hashes: proof_hashes.to_vec(),
    };
    let commitment = expected.commitment();
    let Some(index) = ProofManifestIndex::new(&vote.proof_manifests) else {
        return false;
    };
    !vote.attestations.is_empty()
        && index.covers_exact(&vote.attestations)
        && vote.attestations.iter().all(|claim| {
            claim.proof_acceptance == Some(commitment)
                && claim
                    .proof_acceptance
                    .as_ref()
                    .and_then(|acceptance| index.get(acceptance))
                    == Some(&expected)
        })
}

impl<DB: Database> Engine<DB> {
    pub(super) fn persist_bft_session(
        &mut self,
        session: &BftSession,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let bytes = self.encode_bft_session(session)?;
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(StoreError::Corrupt("BFT session exceeds local storage bound").into());
        }
        let mut batch = Batch::new();
        batch.put(Column::BftSessions, session.chunk_id.to_be_bytes(), bytes);
        self.store_mut().write_observed_batch(batch, true)?;
        Ok(())
    }

    /// Encode `session` with the current boundary context without cloning it.
    fn encode_bft_session(&self, session: &BftSession) -> Result<Vec<u8>, BftLoopError<DB::Error>> {
        let saved = SavedSessionRef {
            spec: self.chain_spec_hash(),
            chunk: &session.chunk,
            validators: self.active_validator_set(),
            validator_root: self.previous_validator_set_root()?,
            proof_hashes: &session.proof_hashes,
            round: session.round(),
            round_started_at_secs: session.round_started_at_secs,
            prevote: session.current_vote(FinalityVotePhase::Prevote),
            precommit: session.current_vote(FinalityVotePhase::Precommit),
            local_identity: session.local_identity,
            local_votes: &session.local_votes,
            highest_lock: session.highest_lock.as_ref(),
            prevote_justification: session.prevote_justification.as_ref(),
            pacemaker: &session.pacemaker,
            proposal: session.proposal.as_ref(),
            valid_value: session.valid_value.as_ref(),
            candidates: &session.candidates,
            selections: &session.selections,
            local_nil_votes: &session.local_nil_votes,
            nil_prevote: session
                .bft
                .current_nil_aggregate(FinalityVotePhase::Prevote),
            nil_precommit: session
                .bft
                .current_nil_aggregate(FinalityVotePhase::Precommit),
            round_certificate: session.round_certificate.as_ref(),
            local_round_report: session.local_round_report.as_ref(),
            pending_votes: session.bft.pending_votes(),
        };
        Ok(borsh::to_vec(&saved).map_err(StoreError::Codec)?)
    }
}

fn decode_saved_session<E>(bytes: &[u8]) -> Result<SavedSession, EngineError<E>> {
    if bytes.len() > MAX_SESSION_BYTES {
        return Err(StoreError::Corrupt("saved BFT session exceeds bound").into());
    }
    Ok(borsh::from_slice(bytes)?)
}
