//! BFT session lifecycle: opening sessions, the round-timeout tick and the
//! observer-facing overview.

use alloc::vec::Vec;

use neutrin0_consensus_chunk_bft::{BftError, ChunkBft, Pacemaker};
use neutrin0_consensus_types::{Chunk, RoundChangeCertificate};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_storage::Database;

use super::{
    BftAction, BftLoopError, BftSession, LocalVoteProgress, PeerQuorumProgress, conflict,
    emit_aggregator_actions,
};
use crate::engine::Engine;

extern crate alloc;

impl<DB: Database> Engine<DB> {
    /// Currently open BFT session for `chunk_id`, if any.
    #[must_use]
    pub fn bft_session(&self, chunk_id: ChunkId) -> Option<&BftSession> {
        self.bft_sessions.get(&chunk_id)
    }

    /// Open a session for an independently prepared proven `chunk`. The local
    /// designated leader emits a signed proposal and its authorized prevote;
    /// other validators wait for that round's authenticated leader proposal.
    ///
    /// Returns the [`BftAction`]s the caller should propagate to the
    /// network. When the local validator's own prevote alone already
    /// crosses the 2/3 prevote quorum (single-validator case), the
    /// follow-on precommit and `QuorumReached` actions are returned
    /// in the same call.
    ///
    /// # Errors
    ///
    /// Returns [`BftLoopError::SessionAlreadyOpen`] if a session for
    /// the same chunk id already exists, or any inner
    /// [`ChunkBft`] / storage error.
    pub fn open_bft_session(
        &mut self,
        chunk: Chunk,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.open_bft_session_at(chunk, 0)
    }

    /// Like [`Self::open_bft_session`] but anchors the session's
    /// round-timeout clock at `now_secs` instead of `0`. Production
    /// callers should pass the current wall-clock Unix-second value
    /// so [`Self::tick_bft_round_timeouts`] can compare against it.
    /// Tests pass a deterministic value to drive timeout scenarios.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::open_bft_session`].
    pub fn open_bft_session_at(
        &mut self,
        chunk: Chunk,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.open_bft_session_initial(chunk, now_secs, None, false)
    }

    /// Open a session without the local leader's own proposal, so test
    /// fixtures can install the fixed one whoever the stake-weighted draw
    /// selects.
    #[cfg(test)]
    pub(crate) fn open_fixture_bft_session_at(
        &mut self,
        chunk: Chunk,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.open_bft_session_initial(chunk, now_secs, None, true)
    }

    pub(super) fn open_bft_session_initial(
        &mut self,
        chunk: Chunk,
        now_secs: u64,
        initial: Option<RoundChangeCertificate>,
        suppress_proposal: bool,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let chunk_id = chunk.chunk_id;
        if chunk_id != self.finalized_next_chunk_id() {
            return Err(conflict());
        }
        if self.bft_sessions.contains_key(&chunk_id) {
            return Err(BftLoopError::SessionAlreadyOpen { chunk_id });
        }
        // A session saved before this node reached the chunk carries its lock
        // and progress; it continues rather than starting over.
        if self.resume_saved_bft_session(chunk_id)? {
            return Ok(Vec::new());
        }
        // Finalized history can be discarded once per new chunk, not on every
        // phase/session write. Unfinalized round positions compact by keyed batch.
        let mut cleanup = neutrin0_storage::Batch::new();
        self.expired_signing_entries(&mut cleanup)?;
        if !cleanup.is_empty() {
            self.store_mut().write_observed_batch(cleanup, true)?;
        }
        let chunk_hash = chunk.hash();
        let round = initial.as_ref().map_or(0, |certificate| certificate.round);
        let bft = self.new_chunk_bft(chunk.clone(), round, self.previous_validator_set_root()?)?;
        let consensus = &self.chain_spec().consensus;
        let mut session = BftSession {
            chunk: chunk.clone(),
            chunk_id,
            chunk_hash,
            proof_hashes: self
                .stored_bft_proof_hashes(&chunk, None)?
                .unwrap_or_default(),
            bft,
            local: LocalVoteProgress::Idle,
            peer_quorum: PeerQuorumProgress::BelowPrevote,
            local_identity: self
                .active_local_voter()
                .as_ref()
                .map(|voter| *voter.public_key_bytes()),
            local_votes: Vec::new(),
            highest_lock: None,
            prevote_justification: None,
            is_local_aggregator: self.local_is_aggregator_for(chunk_id, round),
            subnet: self.subnet_for_chunk(chunk_id),
            last_published_aggregate_stake: [0; 2],
            round_started_at_secs: now_secs,
            pacemaker: Pacemaker::new(
                chunk_id,
                round,
                now_secs,
                consensus.bft_round_timeout_base_secs,
                consensus.bft_round_timeout_step_secs,
            ),
            proposal: None,
            valid_value: None,
            candidates: alloc::collections::BTreeMap::from([(chunk_hash, chunk)]),
            selections: alloc::collections::BTreeMap::new(),
            local_nil_votes: Vec::new(),
            round_certificate: initial,
            local_round_report: None,
        };
        self.recover_session_signing(&mut session)?;
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session.clone());
        let mut actions = if suppress_proposal {
            Vec::new()
        } else {
            self.start_bft_leader_proposal(&mut session, now_secs)?
        };
        self.recompute_quorum_transitions(&mut session, &mut actions)?;
        emit_aggregator_actions(&mut session, &mut actions);
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    /// Configured prevote quorum fraction. Value prevote certificates and
    /// round-change certificates are both weighted under it.
    pub(super) const fn bft_prevote_quorum(&self) -> (u64, u64) {
        let params = &self.chain_spec().consensus;
        (
            params.bft_prevote_quorum_numerator,
            params.bft_prevote_quorum_denominator,
        )
    }

    /// Configured precommit quorum fraction.
    const fn bft_precommit_quorum(&self) -> (u64, u64) {
        let params = &self.chain_spec().consensus;
        (
            params.bft_precommit_quorum_numerator,
            params.bft_precommit_quorum_denominator,
        )
    }

    /// Current-boundary accumulator for `chunk` at `round`, bound to the
    /// authenticated active set and its committed `validator_root`.
    pub(super) fn new_chunk_bft(
        &self,
        chunk: Chunk,
        round: u32,
        validator_root: Hash,
    ) -> Result<ChunkBft, BftError> {
        ChunkBft::with_quorum(
            self.consensus_domain(),
            chunk,
            round,
            self.active_validator_set().to_vec(),
            validator_root,
            self.finalized_seed(),
            self.bft_prevote_quorum(),
            self.bft_precommit_quorum(),
        )
    }

    /// Drive phase deadlines and authenticated round synchronization. Missing or
    /// illegal leader proposals produce nil votes; a local timeout never bypasses
    /// a retained lock. Quorum-certified round entry has no configurable terminal cap.
    /// Integer exhaustion is an explicit protocol error.
    ///
    /// # Errors
    /// Returns signature-reservation, quorum validation or durable storage errors.
    pub fn tick_bft_round_timeouts(
        &mut self,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        if self.certified_execution.is_some() {
            return Ok(Vec::new());
        }
        self.tick_bft_pacemaker(now_secs)
    }
}

/// Observer-facing summary of one live BFT session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent phase flags mirrored as gauges"
)]
pub struct BftSessionOverview {
    /// Total, value prevote/precommit and nil prevote/precommit stake.
    pub stake: [u128; 5],
    /// Chunk under vote.
    pub chunk_id: ChunkId,
    /// Current round.
    pub round: u32,
    /// Local validator has prevoted in the current round.
    pub local_prevoted: bool,
    /// Local validator has precommitted in the current round.
    pub local_precommitted: bool,
    /// A prevote quorum has been observed.
    pub prevote_quorum: bool,
    /// A precommit quorum has been observed.
    pub precommit_quorum: bool,
}

impl<DB: Database> Engine<DB> {
    /// Snapshot every live BFT session for metrics and diagnostics.
    #[must_use]
    pub fn bft_session_overview(&self) -> Vec<BftSessionOverview> {
        self.bft_sessions
            .values()
            .map(|session| BftSessionOverview {
                stake: session.chunk_bft().observed_stake(),
                chunk_id: session.chunk_id(),
                round: session.round(),
                local_prevoted: session.local_prevoted(),
                local_precommitted: session.local_precommitted(),
                prevote_quorum: session.prevote_quorum_observed(),
                precommit_quorum: session.precommit_quorum_observed(),
            })
            .collect()
    }
}
