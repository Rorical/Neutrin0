//! Restart reconstruction: every saved context, quorum and local reservation
//! is authenticated, in a fixed order, before a session is installed.

use alloc::collections::BTreeMap;
use neutrin0_consensus_chunk_bft::ChunkBft;
use neutrin0_consensus_types::{BftProposal, FinalityVoteData, FinalityVotePhase};
use neutrin0_primitives::Hash;
use neutrin0_storage::{Column, Database};

use super::{MAX_LOCAL_PHASE_VOTES, SavedSession, decode_saved_session, local_manifest_matches};
use crate::bft_loop::{
    BftSession, LocalVoteProgress, MAX_BFT_CANDIDATES, PeerQuorumProgress, expected_prevote_unlock,
};
use crate::{Engine, EngineError, StoreError};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    pub(crate) fn restore_bft_sessions(&mut self) -> Result<(), EngineError<DB::Error>> {
        let floor = self.finalized_next_chunk_id();
        let saved = self
            .store()
            .db()
            .iter_column(Column::BftSessions)
            .map_err(StoreError::Database)?;
        let mut sessions = BTreeMap::new();
        for (key, bytes) in saved {
            let id = u64::from_be_bytes(
                key.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("invalid BFT session key"))?,
            );
            if id < floor {
                continue;
            }
            let saved = decode_saved_session(&bytes)?;
            if id > floor {
                if saved.spec != self.chain_spec_hash() || saved.chunk.chunk_id != id {
                    return Err(StoreError::Corrupt(
                        "saved BFT session belongs to another chain or chunk",
                    )
                    .into());
                }
                continue;
            }
            sessions.insert(id, self.restored_bft_session(id, saved)?);
        }
        self.bft_sessions = sessions;
        Ok(())
    }

    /// Resume the session of chunk `id` saved before this node reached that
    /// chunk, exactly as a restart restores it; `false` when none was saved.
    pub(crate) fn resume_saved_bft_session(
        &mut self,
        id: u64,
    ) -> Result<bool, EngineError<DB::Error>> {
        let Some(bytes) = self
            .store()
            .db()
            .get(Column::BftSessions, &id.to_be_bytes())
            .map_err(StoreError::Database)?
        else {
            return Ok(false);
        };
        let session = self.restored_bft_session(id, decode_saved_session(&bytes)?)?;
        self.bft_sessions.insert(id, session);
        Ok(true)
    }

    /// Reauthenticate a saved session of the open chunk `id` and derive its
    /// peer progress.
    fn restored_bft_session(
        &mut self,
        id: u64,
        saved: SavedSession,
    ) -> Result<BftSession, EngineError<DB::Error>> {
        let root = self
            .previous_validator_set_root()
            .map_err(|_| StoreError::Corrupt("cannot restore BFT validator root"))?;
        let mut session = self.restore_bft_session(id, saved, root)?;
        // Saved raw quorums never mark a session finished by themselves;
        // restart applies the same transition rule as live recompute.
        self.advance_peer_quorum(&mut session, root);
        if let Some(lock) = &session.highest_lock {
            self.slashing_monitor.record_prevote_quorum(lock.clone());
        }
        Ok(session)
    }

    /// Reauthenticate one saved session against the committed validator `root`.
    /// Peer progress starts below quorum; the caller derives it afterwards.
    fn restore_bft_session(
        &self,
        id: u64,
        mut saved: SavedSession,
        root: Hash,
    ) -> Result<BftSession, EngineError<DB::Error>> {
        self.check_saved_bft_context(id, &saved, root)?;
        self.verify_saved_round_entry(id, &saved)?;
        // The saved proof hashes are not compared with the receipts held now:
        // preferred receipts legitimately change, and a precommit re-derives
        // its hashes from the proposal's named receipts before signing. They
        // were persisted before any local precommit, so they still match one
        // (checked below) or a journal reservation (checked on recovery).
        // The saved validators equal the authenticated active set checked above.
        let mut bft = self
            .new_chunk_bft(saved.chunk.clone(), saved.round, root)
            .map_err(|_| StoreError::Corrupt("invalid saved BFT context"))?;
        if let Some(proposal) = &saved.proposal {
            bft.set_proposal(proposal.clone())
                .map_err(|_| StoreError::Corrupt("invalid saved leader proposal"))?;
            if saved.prevote_justification != proposal.valid_quorum
                || proposal.round_change_certificate != saved.round_certificate
            {
                return Err(StoreError::Corrupt("saved leader valid value changed").into());
            }
        }
        for vote in [saved.nil_prevote.clone(), saved.nil_precommit.clone()]
            .into_iter()
            .flatten()
        {
            bft.add_nil_vote(vote)
                .map_err(|_| StoreError::Corrupt("invalid saved nil aggregate"))?;
        }
        self.verify_saved_inventory(id, &saved, root)?;
        add_saved_aggregates(&mut bft, &mut saved)?;
        self.verify_saved_lock(id, &saved)?;
        // Every value vote of the round signs the accepted proposal's payment
        // selection; without a proposal no value vote was ever signed.
        let selection = saved.proposal.as_ref().map(BftProposal::selection);
        self.verify_saved_justification(id, &saved, selection)?;
        let (prevoted, precommitted) = self.add_saved_local_nil_votes(&mut bft, id, &saved)?;
        let (prevoted, precommitted) =
            self.add_saved_local_votes(&mut bft, id, &saved, selection, (prevoted, precommitted))?;
        Ok(BftSession {
            chunk_id: id,
            chunk_hash: saved.chunk.hash(),
            chunk: saved.chunk,
            proof_hashes: saved.proof_hashes,
            local: LocalVoteProgress::from_flags(prevoted, precommitted),
            peer_quorum: PeerQuorumProgress::BelowPrevote,
            bft,
            local_identity: saved.local_identity,
            local_votes: saved.local_votes,
            highest_lock: saved.highest_lock,
            prevote_justification: saved.prevote_justification,
            is_local_aggregator: false,
            subnet: self.subnet_for_chunk(id),
            last_published_aggregate_stake: [0; 2],
            round_started_at_secs: saved.round_started_at_secs,
            pacemaker: saved.pacemaker,
            proposal: saved.proposal,
            valid_value: saved.valid_value,
            candidates: saved.candidates,
            selections: saved.selections,
            local_nil_votes: saved.local_nil_votes,
            round_certificate: saved.round_certificate,
            local_round_report: saved.local_round_report,
        })
    }

    /// Refuse a saved session whose chain, chunk, validators, pacemaker
    /// context or inventory bounds differ from the current ones.
    fn check_saved_bft_context(
        &self,
        id: u64,
        saved: &SavedSession,
        root: Hash,
    ) -> Result<(), EngineError<DB::Error>> {
        let params = &self.chain_spec().consensus;
        if saved.spec != self.chain_spec_hash()
            || saved.chunk.chunk_id != id
            || saved.validators != self.active_validator_set()
            || saved.validator_root != root
            || saved.chunk.active_validator_set_root != root
            || saved.local_votes.len() + saved.local_nil_votes.len() > MAX_LOCAL_PHASE_VOTES
            || !saved.pacemaker.context_matches(
                id,
                saved.round,
                params.bft_round_timeout_base_secs,
                params.bft_round_timeout_step_secs,
            )
            || saved.candidates.len() > MAX_BFT_CANDIDATES
            || (saved.round > 0 && saved.round_certificate.is_none())
        {
            return Err(StoreError::Corrupt("saved BFT context mismatch").into());
        }
        Ok(())
    }

    /// Authenticate the saved pacemaker reports and the local round report.
    fn verify_saved_round_entry(
        &self,
        id: u64,
        saved: &SavedSession,
    ) -> Result<(), EngineError<DB::Error>> {
        let domain = self.consensus_domain();
        let prevote_quorum = self.bft_prevote_quorum();
        saved
            .pacemaker
            .validate_saved_reports(domain, &saved.validators, prevote_quorum)
            .map_err(|_| StoreError::Corrupt("invalid saved pacemaker reports"))?;
        if let Some(report) = &saved.local_round_report {
            let identity = saved
                .local_identity
                .ok_or(StoreError::Corrupt("round report has no identity"))?;
            self.verify_saved_round_report(identity, report)?;
            if report.chunk_id != id
                || saved.round.checked_add(1) != Some(report.round)
                || neutrin0_prover_chunk::bft::verify_round_change_using(
                    domain,
                    &saved.validators,
                    report,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err()
            {
                return Err(StoreError::Corrupt("invalid saved local round report").into());
            }
        }
        Ok(())
    }

    /// Check the saved candidate and selection inventories, the valid value
    /// and the round-entry certificate against `id`, `root` and the saved
    /// validators.
    fn verify_saved_inventory(
        &self,
        id: u64,
        saved: &SavedSession,
        root: Hash,
    ) -> Result<(), EngineError<DB::Error>> {
        let domain = self.consensus_domain();
        let prevote_quorum = self.bft_prevote_quorum();
        for (hash, chunk) in &saved.candidates {
            if *hash != chunk.hash()
                || chunk.chunk_id != id
                || chunk.start_height != saved.chunk.start_height
                || chunk.end_height != saved.chunk.end_height
                || chunk.active_validator_set_root != root
            {
                return Err(StoreError::Corrupt("saved candidate inventory mismatch").into());
            }
        }
        if saved
            .selections
            .iter()
            .any(|(key, selection)| *key != selection.commitment())
        {
            return Err(StoreError::Corrupt("saved selection inventory mismatch").into());
        }
        if let Some((chunk, selection, quorum)) = &saved.valid_value
            && (chunk.hash() != quorum.data.chunk_hash
                || selection.commitment() != quorum.data.selection
                || !saved.selections.contains_key(&quorum.data.selection)
                || quorum.data.chunk_id != id
                || quorum.data.round > saved.round
                || !saved.candidates.contains_key(&chunk.hash())
                || neutrin0_prover_chunk::slashing::verify_quorum_using(
                    domain,
                    &saved.validators,
                    quorum,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err())
        {
            return Err(StoreError::Corrupt("invalid saved valid value").into());
        }
        if let Some(certificate) = &saved.round_certificate
            && (certificate.chunk_id != id
                || certificate.round != saved.round
                || neutrin0_prover_chunk::bft::verify_round_change_certificate_using(
                    domain,
                    &saved.validators,
                    certificate,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err())
        {
            return Err(StoreError::Corrupt("invalid saved round certificate").into());
        }
        Ok(())
    }

    /// Authenticate the retained lock quorum.
    fn verify_saved_lock(
        &self,
        id: u64,
        saved: &SavedSession,
    ) -> Result<(), EngineError<DB::Error>> {
        let domain = self.consensus_domain();
        let prevote_quorum = self.bft_prevote_quorum();
        if let Some(lock) = &saved.highest_lock
            && (lock.data.chunk_id != id
                || lock.data.round > saved.round
                || neutrin0_prover_chunk::slashing::verify_quorum_using(
                    domain,
                    &saved.validators,
                    lock,
                    prevote_quorum,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_err())
        {
            return Err(StoreError::Corrupt("invalid saved lock quorum").into());
        }
        Ok(())
    }

    /// Check the saved prevote justification against the proposal's selection.
    fn verify_saved_justification(
        &self,
        id: u64,
        saved: &SavedSession,
        selection: Option<Hash>,
    ) -> Result<(), EngineError<DB::Error>> {
        if let Some(justification) = &saved.prevote_justification {
            let data = FinalityVoteData {
                chunk_id: id,
                chunk_hash: saved.chunk.hash(),
                selection: selection
                    .ok_or(StoreError::Corrupt("saved justification has no proposal"))?,
                round: saved.round,
                phase: FinalityVotePhase::Prevote,
            };
            if self
                .verify_bft_unlock_quorum(&saved.validators, &data, justification)
                .is_err()
            {
                return Err(StoreError::Corrupt("invalid saved prevote justification").into());
            }
        }
        Ok(())
    }

    /// Add the saved local nil votes, returning the phases they cover.
    fn add_saved_local_nil_votes(
        &self,
        bft: &mut ChunkBft,
        id: u64,
        saved: &SavedSession,
    ) -> Result<(bool, bool), EngineError<DB::Error>> {
        let mut prevoted = false;
        let mut precommitted = false;
        for vote in &saved.local_nil_votes {
            let identity = saved
                .local_identity
                .ok_or(StoreError::Corrupt("saved nil has no identity"))?;
            self.verify_saved_nil_vote(identity, vote)?;
            if vote.data.chunk_id != id || vote.data.round != saved.round {
                return Err(StoreError::Corrupt("saved nil target mismatch").into());
            }
            bft.add_nil_vote(vote.clone())
                .map_err(|_| StoreError::Corrupt("invalid saved local nil"))?;
            match vote.data.phase {
                FinalityVotePhase::Prevote if !prevoted => prevoted = true,
                FinalityVotePhase::Precommit if !precommitted => precommitted = true,
                _ => return Err(StoreError::Corrupt("duplicate saved nil phase").into()),
            }
        }
        Ok((prevoted, precommitted))
    }

    /// Add the saved local value votes after the nil votes, returning the
    /// phases the local validator signed.
    fn add_saved_local_votes(
        &self,
        bft: &mut ChunkBft,
        id: u64,
        saved: &SavedSession,
        selection: Option<Hash>,
        (mut prevoted, mut precommitted): (bool, bool),
    ) -> Result<(bool, bool), EngineError<DB::Error>> {
        for vote in &saved.local_votes {
            let identity = saved
                .local_identity
                .ok_or(StoreError::Corrupt("saved local vote has no identity"))?;
            self.verify_saved_local_vote(identity, vote)?;
            if vote.data.chunk_id != id
                || vote.data.chunk_hash != saved.chunk.hash()
                || Some(vote.data.selection) != selection
                || vote.data.round != saved.round
            {
                return Err(StoreError::Corrupt("saved local vote target mismatch").into());
            }
            match vote.data.phase {
                FinalityVotePhase::Prevote if !prevoted => {
                    if vote.attestations.first().is_none_or(|claim| {
                        claim.unlock_quorum
                            != selection.and_then(|selection| {
                                expected_prevote_unlock(
                                    saved.prevote_justification.as_ref(),
                                    saved.highest_lock.as_ref(),
                                    (saved.chunk.hash(), selection),
                                    saved.round,
                                )
                            })
                    }) {
                        return Err(
                            StoreError::Corrupt("saved prevote justification changed").into()
                        );
                    }
                    bft.add_prevote(vote.clone())
                        .map_err(|_| StoreError::Corrupt("invalid saved local prevote"))?;
                    prevoted = true;
                }
                FinalityVotePhase::Precommit if !precommitted => {
                    bft.add_precommit(vote.clone())
                        .map_err(|_| StoreError::Corrupt("invalid saved local precommit"))?;
                    if !local_manifest_matches(vote, &saved.proof_hashes) {
                        return Err(
                            StoreError::Corrupt("saved local proof acceptance mismatch").into()
                        );
                    }
                    precommitted = true;
                }
                _ => return Err(StoreError::Corrupt("saved local vote ordering mismatch").into()),
            }
        }
        Ok((prevoted, precommitted))
    }
}

/// Add the saved peer aggregates and the value votes held before a proposal.
fn add_saved_aggregates<E>(
    bft: &mut ChunkBft,
    saved: &mut SavedSession,
) -> Result<(), EngineError<E>> {
    if let Some(vote) = saved.prevote.take() {
        bft.add_prevote(vote)
            .map_err(|_| StoreError::Corrupt("invalid saved prevote aggregate"))?;
    }
    if let Some(vote) = saved.precommit.take() {
        bft.add_precommit(vote)
            .map_err(|_| StoreError::Corrupt("invalid saved precommit aggregate"))?;
    }
    // Votes held before the proposal exist only while none is accepted.
    if saved.proposal.is_some() && !saved.pending_votes.is_empty() {
        return Err(StoreError::Corrupt("saved pending votes beside a proposal").into());
    }
    for vote in core::mem::take(&mut saved.pending_votes) {
        match vote.data.phase {
            FinalityVotePhase::Prevote => bft.add_prevote(vote),
            FinalityVotePhase::Precommit => bft.add_precommit(vote),
        }
        .map_err(|_| StoreError::Corrupt("invalid saved pending vote"))?;
    }
    Ok(())
}
