//! Detection and verification of objective slashing evidence.
//!
//! Engine-side detection covers objective signed-source offences
//! described in `docs/design/09-consensus.md`:
//!
//! - [`SlashingEvidence::DoubleProposal`]
//! - [`SlashingEvidence::DoublePrevote`]
//! - [`SlashingEvidence::DoublePrecommit`]
//! - [`SlashingEvidence::ConflictingNilVote`]
//! - [`SlashingEvidence::DoubleBftProposal`]
//! - [`SlashingEvidence::InvalidProofSigning`]
//! - [`SlashingEvidence::LockViolation`] (a prior locked precommit
//!   and a later conflicting vote with its signed unlock declaration)
//!
//! Signed DA bundle fraud is verified by the shared portable consensus helper.
//!
//! Detection vs. verification:
//!
//! * **Detection** maintains a [`SlashingMonitor`] keyed by
//!   `(source_chunk, proposer, slot)` for headers and `(validator, chunk, round,
//!   phase)` for single-signer votes plus a `(chunk_id, round,
//!   chunk_hash)`-keyed cache of locally-observed prevote quorums.
//!   Record methods return offence claims when
//!   the same signer has been observed committing to a different
//!   artifact for the same key, or when a later conflicting vote
//!   violates a known signed lock. The lock-quorum cache feed is driven
//!   by the BFT loop via [`SlashingMonitor::record_prevote_quorum`].
//! * **Verification** re-runs the cryptographic checks every
//!   accepting node must independently apply to gossiped evidence.
//!
//! ## Objective lock evidence
//!
//! A later signer must explicitly authenticate its unlock claim. A detector's
//! failure to observe a certificate never establishes a violation. The signed
//! claim binds either the complete certificate or `None`; a reporter cannot
//! remove a valid certificate without invalidating the offender's signature.
//!
//! All evidence variants carry full headers / votes so a replaying
//! node can independently re-verify them without needing the
//! detector's local memory.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use neutrin0_consensus_types::{
    BftProposal, FinalityVotePhase, Header, IndexedNilVote, IndexedVote, NilVote,
    QuorumCertificate, SlashingEvidence, VoteAttestation,
};
use neutrin0_primitives::{ChunkHash, ChunkId, Hash, Slot, ValidatorIndex};

mod capacity;
mod error;
mod locks;
mod verification;

use capacity::{Limits, MONITOR_LIMITS, Observed};

pub use verification::{
    extract_single_signer, finality_vote_signed_message, verify_double_proposal_evidence,
    verify_double_vote_evidence, verify_indexed_vote_signature, verify_lock_violation_evidence,
    verify_proof_acceptance, verify_proof_signing_attribution, verify_vote_attestation,
};
pub(crate) use verification::{verify_indexed_vote_signature_using, verify_vote_attestation_using};

pub use error::SlashingError;

extern crate alloc;

/// Indices of headers and votes already observed by this node.
///
/// Ordinary live observation covers the current chunk and preceding eight
/// authenticated finalized chunks, each map bounded so that a full map evicts
/// from its most prolific signer, never stopping observation of the others.
/// Reporter forensic replay follows its separate authenticated historical
/// policy. Retention advances through
/// [`Self::retain_history_window`] using locally authenticated finality;
/// peer-declared slots and chunk ids never evict evidence.
#[derive(Debug)]
pub struct SlashingMonitor {
    /// Durable reporter replay uses its provisioned storage instead of forensic cache quotas.
    reporter: bool,
    /// `(source_chunk, proposer_index, slot) → header` previously accepted.
    seen_headers: Observed<HeaderKey, Header, Signer>,
    /// `(validator_index, chunk_id, round, phase) → vote` previously
    /// accepted from a single-signer aggregation bit set.
    seen_votes: Observed<VoteKey, IndexedVote, Signer>,
    seen_nil_votes: Observed<VoteKey, IndexedNilVote, Signer>,
    seen_bft_proposals: Observed<ProposalKey, BftProposal, Signer>,
    /// Prevote quorums the local node has observed reach 2/3 stake,
    /// keyed by `(chunk_id, round, chunk_hash, selection)`: a value is the
    /// chunk with its payment selection (design 08). Populated through
    /// [`Self::record_prevote_quorum`], including whenever a BFT session's
    /// shared quorum transition first crosses a value prevote quorum, live,
    /// during signing recovery or on restart. Consumed by the cross-round
    /// `LockViolation` synthesiser in [`Self::record_indexed_vote`].
    observed_prevote_quorums: Observed<QuorumKey, QuorumCertificate, ChunkId>,
    /// Explicit authenticated claims; local absence of a QC is not slashable.
    attestations: Observed<AttestationKey, VoteAttestation, Signer>,
}

type HeaderKey = (ChunkId, ValidatorIndex, Slot);
type VoteKey = (ValidatorIndex, ChunkId, u32, FinalityVotePhase);
type ProposalKey = (ChunkId, u32, ValidatorIndex);
type QuorumKey = (ChunkId, u32, ChunkHash, Hash);
type AttestationKey = (
    ValidatorIndex,
    ChunkId,
    u32,
    ChunkHash,
    Hash,
    FinalityVotePhase,
);
/// A validator seat in a chunk's set, which owns what it signed there.
type Signer = (ChunkId, ValidatorIndex);

const fn header_signer(key: &HeaderKey) -> Signer {
    (key.0, key.1)
}

const fn vote_signer(key: &VoteKey) -> Signer {
    (key.1, key.0)
}

const fn proposal_signer(key: &ProposalKey) -> Signer {
    (key.0, key.2)
}

const fn quorum_chunk(key: &QuorumKey) -> ChunkId {
    key.0
}

const fn attestation_signer(key: &AttestationKey) -> Signer {
    (key.1, key.0)
}

/// Weight of values bounded by entries alone.
const fn weightless<V>(_: &V) -> usize {
    0
}

impl Default for SlashingMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SlashingMonitor {
    /// Create an empty monitor whose retention is advanced by authenticated finality.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reporter: false,
            seen_headers: Observed::new(header_signer, weightless),
            seen_votes: Observed::new(vote_signer, weightless),
            seen_nil_votes: Observed::new(vote_signer, weightless),
            seen_bft_proposals: Observed::new(proposal_signer, encoded_size),
            observed_prevote_quorums: Observed::new(quorum_chunk, encoded_size),
            attestations: Observed::new(attestation_signer, encoded_size),
        }
    }

    /// Bounds of the observation maps; a reporter's durable replay has none.
    fn limits(&self) -> Option<Limits> {
        (!self.reporter).then_some(MONITOR_LIMITS)
    }

    pub(crate) fn for_reporter() -> Self {
        Self {
            reporter: true,
            ..Self::new()
        }
    }

    /// Discard observations below an authenticated accountability history floor.
    ///
    /// Callers must derive the floor from locally verified finalized history,
    /// never from a peer's claimed slot, height, or chunk id.
    pub fn retain_history_window(&mut self, first_chunk: ChunkId) {
        self.seen_headers.retain(|key| key.0 >= first_chunk);
        self.seen_votes.retain(|key| key.1 >= first_chunk);
        self.seen_nil_votes.retain(|key| key.1 >= first_chunk);
        self.seen_bft_proposals.retain(|key| key.0 >= first_chunk);
        self.observed_prevote_quorums
            .retain(|key| key.0 >= first_chunk);
        self.attestations.retain(|key| key.1 >= first_chunk);
    }

    /// Record a signed header. If the same proposer has previously
    /// been observed signing a *different* header at the same slot,
    /// return [`SlashingEvidence::DoubleProposal`].
    ///
    /// Exact duplicate headers (same hash) are silently ignored.
    /// Callers should verify the header signature **before**
    /// recording and authenticate the source chunk's validator context;
    /// [`Engine::observe_header_for_slashing`](crate::Engine::observe_header_for_slashing) does this automatically.
    pub fn record_header(
        &mut self,
        source_chunk: ChunkId,
        header: &Header,
    ) -> Option<SlashingEvidence> {
        let key = (source_chunk, header.proposer_index, header.slot);
        match self.seen_headers.get(&key) {
            Some(existing) if existing.hash() != header.hash() => {
                Some(SlashingEvidence::DoubleProposal {
                    proposer_index: header.proposer_index,
                    header_a: existing.clone(),
                    header_b: header.clone(),
                })
            }
            Some(_) => None,
            None => {
                let limits = self.limits();
                self.seen_headers.insert(limits, key, header.clone());
                None
            }
        }
    }

    /// Record a single-signer indexed vote.
    ///
    /// Returns evidence under three rules, checked in order:
    ///
    /// 1. **Same-round equivocation** — a validator that has already
    ///    been observed voting for a *different* value (chunk hash or payment
    ///    selection) at the
    ///    exact same `(chunk_id, round, phase)` produces
    ///    [`SlashingEvidence::DoublePrevote`] /
    ///    [`SlashingEvidence::DoublePrecommit`].
    /// 2. **Cross-round lock violation** requires a prior conflicting
    ///    precommit, its prevote quorum, and an authenticated attestation
    ///    from the later signer. The engine rechecks the synthesized evidence
    ///    before returning it; a valid signed unlock suppresses the report.
    /// 3. **No equivocation** — exact-duplicate or same-hash votes
    ///    return `None`. The vote is still recorded for future
    ///    equivocation lookups.
    ///
    /// Aggregated votes carrying more than one signer bit do not
    /// participate here; the caller extracts the single signer via
    /// [`extract_single_signer`] first.
    pub fn record_indexed_vote(
        &mut self,
        validator_index: ValidatorIndex,
        vote: &IndexedVote,
    ) -> Option<SlashingEvidence> {
        let key = (
            validator_index,
            vote.data.chunk_id,
            vote.data.round,
            vote.data.phase,
        );
        if let Some(nil_vote) = self.seen_nil_votes.get(&key) {
            return Some(SlashingEvidence::ConflictingNilVote {
                validator_index,
                value_vote: vote.clone(),
                nil_vote: nil_vote.clone(),
            });
        }
        // Rule 1: same-round equivocation. Caught before any insert
        // / cross-round work because the existing entry at the same
        // key always takes precedence.
        if let Some(existing) = self.seen_votes.get(&key) {
            if !existing.data.same_value(&vote.data) {
                let evidence = match vote.data.phase {
                    FinalityVotePhase::Prevote => SlashingEvidence::DoublePrevote {
                        validator_index,
                        vote_a: existing.clone(),
                        vote_b: vote.clone(),
                    },
                    FinalityVotePhase::Precommit => SlashingEvidence::DoublePrecommit {
                        validator_index,
                        vote_a: existing.clone(),
                        vote_b: vote.clone(),
                    },
                };
                return Some(evidence);
            }
            // An explicit attestation may arrive after the ordinary vote.
            // Revisit cross-round evidence instead of treating that arrival
            // as a duplicate with no new attribution information.
            return self.try_synthesize_lock_violation(validator_index, vote);
        }
        let limits = self.limits();
        if !self.seen_votes.insert(limits, key, vote.clone()) {
            return None;
        }

        // A prior locked precommit constrains both later vote phases.
        self.try_synthesize_lock_violation(validator_index, vote)
    }

    /// Record individually authenticated nil declarations, including delayed arrivals.
    pub fn record_nil_vote(&mut self, vote: &NilVote) -> Vec<SlashingEvidence> {
        let mut evidence = Vec::new();
        for claim in &vote.attestations {
            let key = (
                claim.validator_index,
                vote.data.chunk_id,
                vote.data.round,
                vote.data.phase,
            );
            let nil_vote = IndexedNilVote {
                data: vote.data.clone(),
                signature: claim.vote_signature,
            };
            if let Some(value_vote) = self.seen_votes.get(&key) {
                evidence.push(SlashingEvidence::ConflictingNilVote {
                    validator_index: claim.validator_index,
                    value_vote: value_vote.clone(),
                    nil_vote: nil_vote.clone(),
                });
            }
            let limits = self.limits();
            self.seen_nil_votes.insert(limits, key, nil_vote);
        }
        evidence
    }

    /// Preserve independently signed conflicting leader values (chunk and
    /// payment selection) for the same round.
    pub fn record_bft_proposal(&mut self, proposal: &BftProposal) -> Option<SlashingEvidence> {
        let key = (
            proposal.chunk.chunk_id,
            proposal.round,
            proposal.proposer_index,
        );
        match self.seen_bft_proposals.get(&key) {
            Some(prior)
                if prior.chunk.hash() != proposal.chunk.hash()
                    || prior.selection() != proposal.selection() =>
            {
                Some(SlashingEvidence::DoubleBftProposal {
                    proposer_index: proposal.proposer_index,
                    proposal_a: prior.clone(),
                    proposal_b: proposal.clone(),
                })
            }
            Some(_) => None,
            None => {
                let limits = self.limits();
                self.seen_bft_proposals
                    .insert(limits, key, proposal.clone());
                None
            }
        }
    }

    /// Record an observed 2/3 prevote quorum so the
    /// [`Self::record_indexed_vote`] cross-round detector can
    /// attach lock evidence when it later sees a conflicting
    /// precommit. Called by the BFT loop once per
    /// `(chunk_id, round, chunk_hash)` quorum transition.
    ///
    /// Subsequent calls for the same key are no-ops — the first
    /// observation is sufficient lock evidence and replacing the
    /// stored aggregate with a later (larger) one is unnecessary.
    pub fn record_prevote_quorum(&mut self, quorum: QuorumCertificate) {
        if quorum.data.phase != FinalityVotePhase::Prevote {
            return;
        }
        let key = (
            quorum.data.chunk_id,
            quorum.data.round,
            quorum.data.chunk_hash,
            quorum.data.selection,
        );
        if self.observed_prevote_quorums.contains_key(&key) {
            return;
        }
        // Quorums have no single signer; a chunk with many rounds yields.
        let limits = self.limits();
        self.observed_prevote_quorums.insert(limits, key, quorum);
    }

    pub(crate) fn prevote_quorum_is_observed(&self, quorum: &QuorumCertificate) -> bool {
        self.observed_prevote_quorums.contains_key(&(
            quorum.data.chunk_id,
            quorum.data.round,
            quorum.data.chunk_hash,
            quorum.data.selection,
        ))
    }

    /// Record a claim after verifying its signature against the chunk's set.
    pub fn record_attestation(&mut self, attestation: VoteAttestation) {
        let data = &attestation.vote;
        let key = (
            attestation.validator_index,
            data.chunk_id,
            data.round,
            data.chunk_hash,
            data.selection,
            data.phase,
        );
        // A later claim for the same key replaces the earlier one in place.
        let limits = self.limits();
        if self.attestations.contains_key(&key) {
            self.attestations.replace(limits, key, attestation);
            return;
        }
        self.attestations.insert(limits, key, attestation);
    }

    /// Headers observed at heights of chunk `chunk_id`, in proposer and slot
    /// order.
    pub fn headers_in_chunk(&self, chunk_id: ChunkId) -> impl Iterator<Item = &Header> {
        self.seen_headers
            .range((chunk_id, 0, 0)..=(chunk_id, ValidatorIndex::MAX, Slot::MAX))
            .map(|(_, header)| header)
    }

    /// Number of distinct (source chunk, proposer, slot) headers indexed.
    #[must_use]
    pub fn headers_tracked(&self) -> usize {
        self.seen_headers.len()
    }

    /// Number of distinct (validator, chunk, round, phase) votes indexed.
    #[must_use]
    pub fn votes_tracked(&self) -> usize {
        self.seen_votes.len()
    }
}

/// Retain `map` entries whose key satisfies `keep`, subtracting each removed
/// entry's encoded length from its running byte total `bytes`.
/// Encoded size of an observation; one that cannot encode never fits.
fn encoded_size<V: borsh::BorshSerialize>(value: &V) -> usize {
    borsh::object_length(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
