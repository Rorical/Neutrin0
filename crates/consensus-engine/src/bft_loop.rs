//! Live multi-validator chunk-BFT driver.
//!
//! Network voting and local finalization share the same durable signing path.
//! Exact signing reservations are synchronized before accessing the key, and
//! complete sessions commit before any broadcast action is returned. Restart
//! validates saved votes and quorums and finishes interrupted reservations.
//!
//! A proof-ready chunk opens a durable session without choosing a local fork.
//! Its deterministic active-set leader signs the round proposal; followers only
//! prevote after the proposal and complete branch are authenticated. Missing or
//! incompatible proposals produce explicit nil votes at phase deadlines. Value
//! prevote quorums create valid values; local value precommits retain their locks.
//! Signed round reports synchronize entry under an independently checked quorum
//! certificate, carried by every nonzero-round leader proposal. Only a complete
//! Chunk receipt can commit the resulting value finality certificate.
//!
//! The session deliberately does not own the network. Every external
//! effect is funnelled through [`BftAction`]; the engine can be tested without
//! spinning up libp2p.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};

use neutrin0_consensus_chunk_bft::{ChunkBft, Pacemaker};
use neutrin0_consensus_types::{
    BftProposal, Chunk, FinalityVote, FinalityVoteData, FinalityVotePhase, NilVote,
    PaymentSelection, QuorumCertificate, RoundChange, RoundChangeCertificate,
};
#[cfg(test)]
use neutrin0_primitives::{BitVec, ConsensusDomain};
use neutrin0_primitives::{BlockHash, BlsPublicKey, ChunkHash, ChunkId, Hash};

use crate::error::EngineError;
#[cfg(test)]
use crate::proposer::ProposerKey;
use crate::signing::SigningViolation;

extern crate alloc;

mod actions;
mod candidates;
mod liveness;
mod local_voter;
mod persistence;
mod quorum;
mod sessions;
mod votes;

#[cfg(test)]
mod tests;

pub use actions::{BftAction, BftLoopError, BftQuorumIdentity};
use quorum::emit_aggregator_actions;
pub use sessions::BftSessionOverview;

/// Bound on retained proven candidate branches per session. Eviction protects
/// at most five live quorum dependencies within this bound.
const MAX_BFT_CANDIDATES: usize = 8;

/// A request that would violate the local signing rules or the current boundary.
pub(crate) fn conflict<E>() -> BftLoopError<E> {
    EngineError::Signing(SigningViolation::Conflict).into()
}

/// Valid-value order: a later round wins, then the larger target hash and
/// selection.
const fn qc_rank(quorum: &QuorumCertificate) -> (u32, ChunkHash, Hash) {
    (
        quorum.data.round,
        quorum.data.chunk_hash,
        quorum.data.selection,
    )
}

/// Progress of the local validator's own signed votes inside one
/// BFT round. Value and nil share each durable phase reservation; a signed
/// phase never retraces before authenticated entry into a later round.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
enum LocalVoteProgress {
    /// Local validator has not yet recorded its prevote (or no local
    /// voter is configured).
    Idle,
    /// Local validator's prevote has been recorded; precommit pending.
    Prevoted,
    /// Local validator's precommit has been recorded.
    Precommitted,
}

impl LocalVoteProgress {
    /// Progress after a durable local value or nil signature in `phase`.
    const fn after(phase: FinalityVotePhase) -> Self {
        match phase {
            FinalityVotePhase::Prevote => Self::Prevoted,
            FinalityVotePhase::Precommit => Self::Precommitted,
        }
    }

    /// Progress implied by the durable local phase reservations.
    const fn from_flags(prevoted: bool, precommitted: bool) -> Self {
        if precommitted {
            Self::Precommitted
        } else if prevoted {
            Self::Prevoted
        } else {
            Self::Idle
        }
    }
}

/// Progress of the *peer* quorum-stake totals observed by the local
/// chunk-BFT accumulator. Monotonic within a round; reset only by certified
/// entry into a later round.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
enum PeerQuorumProgress {
    /// Less than 2/3 prevote stake accumulated so far.
    BelowPrevote,
    /// 2/3 prevote stake observed; precommit quorum still pending.
    PrevoteQuorumObserved,
    /// 2/3 precommit stake observed — finalisation is unlocked.
    PrecommitQuorumObserved,
}

/// Per-chunk BFT state combining the [`ChunkBft`] accumulator with
/// the local validator's participation bookkeeping.
#[derive(Clone, Debug)]
pub struct BftSession {
    chunk: Chunk,
    chunk_id: ChunkId,
    chunk_hash: ChunkHash,
    proof_hashes: Vec<neutrin0_primitives::Hash>,
    bft: ChunkBft,
    local: LocalVoteProgress,
    peer_quorum: PeerQuorumProgress,
    local_identity: Option<BlsPublicKey>,
    local_votes: Vec<FinalityVote>,
    highest_lock: Option<QuorumCertificate>,
    prevote_justification: Option<QuorumCertificate>,
    /// Whether the local validator was elected as an aggregator for
    /// `(chunk_id, current_round)`. Re-derived inside
    /// [`Engine::tick_bft_round_timeouts`](crate::Engine::tick_bft_round_timeouts) when a round advance fires.
    is_local_aggregator: bool,
    /// Subnet routing for the union-aggregated vote when this node
    /// publishes aggregate prevotes / precommits.
    subnet: u8,
    /// Aggregate prevote and precommit stake last published as aggregator
    /// actions, in phase order; used to suppress re-publishing the same union
    /// vote when no new partial votes arrived. Never persisted.
    last_published_aggregate_stake: [u128; 2],
    /// Durable Unix-second start anchor for this entered round. Phase deadlines
    /// live in the pacemaker and reset when a timely authenticated quorum arrives.
    round_started_at_secs: u64,
    /// Phase deadlines and authenticated round synchronization.
    pacemaker: Pacemaker,
    /// Signed leader proposal accepted for this round.
    proposal: Option<BftProposal>,
    /// Highest observed valid value, independent of the local precommit lock:
    /// the chunk, the payment selection its quorum signed and the quorum.
    valid_value: Option<(Chunk, PaymentSelection, QuorumCertificate)>,
    /// Independently proven branches available to the current leader.
    candidates: alloc::collections::BTreeMap<ChunkHash, Chunk>,
    /// Payment selections of accepted proposals and justified candidates by
    /// commitment, so a leader re-proposes a valid value exactly (design 08).
    selections: alloc::collections::BTreeMap<Hash, PaymentSelection>,
    /// Original local nil signatures; nil never erases a retained lock.
    local_nil_votes: Vec<NilVote>,
    round_certificate: Option<RoundChangeCertificate>,
    local_round_report: Option<RoundChange>,
}

impl BftSession {
    /// Statement keys of every receipt this session's accepted proposal,
    /// valid value or known selections name. Votes, re-proposals and proving
    /// need exactly these receipts, so the store never evicts them.
    pub(crate) fn named_receipt_keys(
        &self,
    ) -> impl Iterator<Item = neutrin0_primitives::Hash> + '_ {
        self.proposal
            .iter()
            .flat_map(|proposal| proposal.receipts.iter())
            .chain(
                self.valid_value
                    .iter()
                    .flat_map(|(_, selection, _)| selection.receipts.iter()),
            )
            .chain(
                self.selections
                    .values()
                    .flat_map(|selection| selection.receipts.iter()),
            )
            .map(|choice| choice.statement_key)
    }

    /// Chunk id this session votes on.
    #[must_use]
    pub const fn chunk_id(&self) -> ChunkId {
        self.chunk_id
    }

    /// Canonical chunk hash bound by every vote in this session.
    #[must_use]
    pub const fn chunk_hash(&self) -> ChunkHash {
        self.chunk_hash
    }

    /// A retained candidate for an exact QC target, including a noncurrent branch.
    /// Callers serving it must reauthenticate its stored branch and receipts.
    #[must_use]
    pub fn candidate_by_hash(&self, hash: &Hash) -> Option<&Chunk> {
        self.candidates.get(hash)
    }

    /// Last block of the current round's candidate branch.
    #[must_use]
    pub const fn end_block_hash(&self) -> BlockHash {
        self.chunk.end_block_hash
    }

    /// Statement keys the accepted proposal names, one per height, or `None`
    /// before this round has a proposal (design 08).
    #[must_use]
    pub fn named_receipts(&self) -> Option<Vec<Hash>> {
        self.proposal.as_ref().map(BftProposal::receipt_keys)
    }

    /// Whether the local validator has recorded its own prevote.
    #[must_use]
    pub const fn local_prevoted(&self) -> bool {
        matches!(
            self.local,
            LocalVoteProgress::Prevoted | LocalVoteProgress::Precommitted
        )
    }

    /// Whether the local validator has recorded its own precommit.
    #[must_use]
    pub const fn local_precommitted(&self) -> bool {
        matches!(self.local, LocalVoteProgress::Precommitted)
    }

    /// Whether the 2/3 prevote quorum has been observed at least once.
    #[must_use]
    pub const fn prevote_quorum_observed(&self) -> bool {
        matches!(
            self.peer_quorum,
            PeerQuorumProgress::PrevoteQuorumObserved | PeerQuorumProgress::PrecommitQuorumObserved
        )
    }

    /// Whether the 2/3 precommit quorum has been observed at least once.
    /// The engine surfaces this as the trigger to call
    /// [`Engine::finalize_chunk`](crate::Engine::finalize_chunk).
    #[must_use]
    pub const fn precommit_quorum_observed(&self) -> bool {
        matches!(
            self.peer_quorum,
            PeerQuorumProgress::PrecommitQuorumObserved
        )
    }

    /// Borrow the underlying [`ChunkBft`] accumulator. Finalisation
    /// reads the accumulated aggregate votes through this handle.
    #[must_use]
    pub const fn chunk_bft(&self) -> &ChunkBft {
        &self.bft
    }

    /// Whether the local validator was elected into the VRF
    /// aggregator committee for this chunk and round.
    #[must_use]
    pub const fn is_local_aggregator(&self) -> bool {
        self.is_local_aggregator
    }

    /// Current BFT round.
    #[must_use]
    pub const fn round(&self) -> u32 {
        self.bft.round()
    }

    /// Wall-clock anchor (Unix seconds) for the current round. Used
    /// by [`Engine::tick_bft_round_timeouts`](crate::Engine::tick_bft_round_timeouts) to decide whether the
    /// round needs to advance.
    #[must_use]
    pub const fn round_started_at_secs(&self) -> u64 {
        self.round_started_at_secs
    }

    /// Highest authenticated prevote quorum retained across round changes.
    #[must_use]
    pub const fn highest_lock_quorum(&self) -> Option<&QuorumCertificate> {
        self.highest_lock.as_ref()
    }

    /// Exact target and certificate identity for proof work created by this session.
    #[must_use]
    pub fn quorum_identity(&self) -> Option<BftQuorumIdentity> {
        let certificate = self.certificate()?;
        Some(BftQuorumIdentity::from_certificate(&certificate))
    }

    /// Complete authenticated certificate, including both phases and the signed proposal.
    #[must_use]
    pub fn certificate(&self) -> Option<neutrin0_consensus_types::FinalityCert> {
        self.bft
            .try_finalize(self.chunk.active_validator_set_root)
            .ok()?
    }

    /// Value-vote target of the current candidate and round in `phase`: the
    /// chunk with the accepted proposal's payment selection (design 08).
    /// `None` before this round has a proposal, when no value may be signed:
    /// signing one value and then another would be equivocation.
    fn vote_data(&self, phase: FinalityVotePhase) -> Option<FinalityVoteData> {
        let proposal = self.proposal.as_ref()?;
        Some(FinalityVoteData {
            chunk_id: self.chunk_id,
            chunk_hash: self.chunk_hash,
            selection: proposal.selection(),
            round: self.round(),
            phase,
        })
    }

    /// Payment selection of this round's accepted proposal, which every value
    /// vote of the round signs (design 08).
    #[must_use]
    pub fn selection(&self) -> Option<Hash> {
        self.proposal.as_ref().map(BftProposal::selection)
    }

    /// Unlock declaration the local prevote signs for the current target.
    ///
    /// Lock-violation evidence pairs a later vote with *any* earlier conflicting
    /// precommit and demands a signed unlock QC newer than that precommit. A
    /// validator whose lock moved from A to B through a valid precommit must
    /// therefore keep declaring B's locking QC when it prevotes B again, even
    /// when the leader proposal carries no QC; otherwise its own honest
    /// signatures are admissible evidence against it. The declared QC is the
    /// higher-round one of the proposal's valid QC and the retained lock when
    /// the lock targets this candidate; a lock from this round cannot justify
    /// a prevote of this round.
    fn prevote_unlock(&self) -> Option<QuorumCertificate> {
        expected_prevote_unlock(
            self.prevote_justification.as_ref(),
            self.highest_lock.as_ref(),
            (self.chunk_hash, self.selection()?),
            self.round(),
        )
    }

    /// Union of every accepted current-target value vote in `phase`.
    fn current_vote(&self, phase: FinalityVotePhase) -> Option<FinalityVote> {
        let aggregate = self.bft.current_aggregate(phase)?;
        Some(FinalityVote {
            attestations: self.bft.current_attestations(phase),
            proof_manifests: self.bft.current_proof_manifests(phase),
            aggregation_bits: aggregate.aggregation_bits,
            signature: aggregate.signature,
            data: self.vote_data(phase)?,
        })
    }

    /// Prevote certificate formed by the current target's accepted prevotes.
    fn current_prevote_quorum(&self) -> Option<QuorumCertificate> {
        let aggregate = self.bft.current_aggregate(FinalityVotePhase::Prevote)?;
        Some(QuorumCertificate {
            data: self.vote_data(FinalityVotePhase::Prevote)?,
            aggregate,
        })
    }

    /// Record a completed durable local signature in `phase` by `identity`.
    const fn record_local_signature(&mut self, phase: FinalityVotePhase, identity: BlsPublicKey) {
        self.local = LocalVoteProgress::after(phase);
        self.local_identity = Some(identity);
    }
}

/// Unlock QC a prevote of `chunk_hash` at `round` declares, from the leader's
/// valid QC and the retained lock. See [`BftSession::prevote_unlock`].
pub(super) fn expected_prevote_unlock(
    justification: Option<&QuorumCertificate>,
    lock: Option<&QuorumCertificate>,
    (chunk_hash, selection): (ChunkHash, Hash),
    round: u32,
) -> Option<QuorumCertificate> {
    let lock = lock.filter(|lock| {
        lock.data.chunk_hash == chunk_hash
            && lock.data.selection == selection
            && lock.data.round < round
    });
    match (justification, lock) {
        (Some(justification), Some(lock)) if lock.data.round > justification.data.round => {
            Some(lock.clone())
        }
        (Some(justification), _) => Some(justification.clone()),
        (None, lock) => lock.cloned(),
    }
}

/// Payment selection of the fixture proposals unit tests install, which their
/// value votes sign: slot zero, no receipt and no ratification (design 08).
#[cfg(test)]
pub(crate) fn fixture_selection() -> Hash {
    neutrin0_consensus_types::bft::selection_commitment(0, &[], &[])
}

/// Build and sign the local validator's vote for `(chunk_id, round,
/// chunk_hash, phase)` with the fixture selection.
#[cfg(test)]
fn build_local_vote(
    chunk_id: ChunkId,
    chunk_hash: ChunkHash,
    round: u32,
    phase: FinalityVotePhase,
    domain: ConsensusDomain,
    voter: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id,
        round,
        chunk_hash,
        selection: fixture_selection(),
        phase,
    };
    let signature = voter.sign_finality_vote(domain, &data);
    let voter_index = voter.validator_index();
    let voter_position = usize::try_from(voter_index).expect("u32 fits usize on supported targets");
    let mut bits = BitVec::default();
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }
    let proof_hashes = if phase == FinalityVotePhase::Precommit {
        vec![[1; 32]]
    } else {
        Vec::new()
    };
    let proof_manifests = if proof_hashes.is_empty() {
        Vec::new()
    } else {
        vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: proof_hashes.clone(),
        }]
    };
    FinalityVote {
        proof_manifests,
        attestations: vec![voter.attest_vote(domain, data.clone(), proof_hashes, None)],
        aggregation_bits: bits,
        data,
        signature,
    }
}
