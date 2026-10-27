//! The historical participation vote lane: authenticating committed
//! acknowledgements and admitting locally retained omitted votes.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use neutrin0_consensus_types::history::is_recent_history_index;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use neutrin0_storage::Database;

use crate::{Engine, FinalizeError};

/// What the blocks before one in its chunk already put in the vote lane.
#[derive(Default)]
pub(super) struct InheritedVotes {
    /// Encoded lane bytes, counted against the chunk's budget.
    pub(super) bytes: usize,
    /// Source seats already acknowledged; each fills once per chunk.
    pub(super) seats: alloc::collections::BTreeSet<(u64, u32)>,
}

/// Admit selected, individually authenticated compact ACKs in one bounded pass.
/// Complete signed acceptance sources stay in availability/reporter storage.
fn admit_participation_votes(
    body: &mut neutrin0_consensus_types::Body,
    selected: Vec<neutrin0_consensus_types::participation::ParticipationVote>,
    inherited_bytes: usize,
) -> Result<(), String> {
    use neutrin0_consensus_types::participation::{
        MAX_PARTICIPATION_ACKS, MAX_PARTICIPATION_VOTE_BYTES, vote_lane_bytes, vote_lane_is_bounded,
    };
    if !vote_lane_is_bounded(&body.participation_acks) {
        return Err("invalid supplied historical vote lane".into());
    }
    let mut bytes = vote_lane_bytes(&body.participation_acks)
        .map_err(|_| "historical vote lane encoding failed")?
        .checked_add(inherited_bytes)
        .ok_or("historical vote lane byte overflow")?;
    if bytes > MAX_PARTICIPATION_VOTE_BYTES {
        return Err("historical vote lane exceeds chunk budget".into());
    }
    let mut count = body.participation_acks.len();
    let mut admitted = Vec::new();
    for vote in selected {
        let size =
            borsh::object_length(&vote).map_err(|_| "compact acknowledgement encoding failed")?;
        if count == MAX_PARTICIPATION_ACKS || size > MAX_PARTICIPATION_VOTE_BYTES - bytes {
            continue;
        }
        bytes += size;
        count += 1;
        admitted.push(vote);
    }
    body.participation_acks.extend(admitted);
    Ok(())
}

/// The candidates the runtime does not already count as participating, in
/// bounded coverage queries, each added to `already` as it is selected.
fn uncovered_votes(
    executor: &dyn neutrin0_proof_system::ErasedBlockExecutor,
    runtime: Hash,
    state: &neutrin0_trie::Trie<neutrin0_trie::Poseidon2Hasher>,
    candidates: BTreeMap<
        neutrin0_consensus_types::participation::ParticipationAcknowledgement,
        neutrin0_consensus_types::participation::ParticipationVote,
    >,
    already: &mut alloc::collections::BTreeSet<
        neutrin0_consensus_types::participation::ParticipationAcknowledgement,
    >,
) -> Result<Vec<neutrin0_consensus_types::participation::ParticipationVote>, String> {
    use neutrin0_consensus_types::participation::MAX_PARTICIPATION_ACKS;
    use neutrin0_runtime_abi::operational::{
        EvidenceCoverage, EvidenceCoverageRequest, MAX_REPORTER_STATUS_IDENTITIES,
        QUERY_EVIDENCE_COVERAGE,
    };
    let candidates: Vec<_> = candidates.into_iter().collect();
    let mut selected = Vec::new();
    for batch in candidates.chunks(MAX_REPORTER_STATUS_IDENTITIES) {
        let requests: Vec<_> = batch
            .iter()
            .map(|(record, _)| EvidenceCoverageRequest {
                identity: record.identity,
                offence_id: None,
                liveness: Some((record.chunk_id, record.address)),
            })
            .collect();
        let response = executor.query(
            &neutrin0_runtime_abi::QueryRequest {
                method: QUERY_EVIDENCE_COVERAGE.into(),
                args: borsh::to_vec(&requests).map_err(|error| error.to_string())?,
            },
            runtime,
            state,
        )?;
        if response.code != 0 {
            return Err("participation coverage query unavailable".into());
        }
        let statuses: Vec<EvidenceCoverage> =
            borsh::from_slice(&response.payload).map_err(|_| "malformed participation coverage")?;
        if statuses.len() != batch.len() {
            return Err("incomplete participation coverage".into());
        }
        for ((record, vote), status) in batch.iter().zip(statuses) {
            if status.participated
                || already.contains(record)
                || already.len() >= MAX_PARTICIPATION_ACKS
            {
                continue;
            }
            already.insert(record.clone());
            selected.push(vote.clone());
        }
    }
    Ok(selected)
}

impl<DB: Database> Engine<DB> {
    /// Authenticate positive participation in the committed historical vote lane.
    ///
    /// # Errors
    /// Rejects unavailable history, stale sources, a repeated source seat or
    /// malformed signed votes.
    pub fn participation_acknowledgements(
        &self,
        height: u64,
        body: &neutrin0_consensus_types::Body,
    ) -> Result<
        Vec<neutrin0_consensus_types::participation::ParticipationAcknowledgement>,
        FinalizeError<DB::Error>,
    > {
        let incoming = self
            .chunk_of_height(height)
            .ok_or(ProofError::InvalidWitness)?;
        if !neutrin0_consensus_types::participation::vote_lane_is_bounded(&body.participation_acks)
        {
            return Err(ProofError::InvalidWitness.into());
        }
        let mut records = alloc::collections::BTreeSet::new();
        let mut seats = alloc::collections::BTreeSet::new();
        let mut sources = BTreeMap::new();
        for vote in &body.participation_acks {
            // A repeated seat adds no acknowledgement, only signature work.
            if !is_recent_history_index(vote.data.chunk_id, incoming)
                || !seats.insert(vote.source_seat())
            {
                return Err(ProofError::InvalidWitness.into());
            }
            if let alloc::collections::btree_map::Entry::Vacant(entry) =
                sources.entry(vote.data.chunk_id)
            {
                entry.insert(
                    self.execution_history_chunk(vote.data.chunk_id, incoming)?
                        .ok_or(ProofError::InvalidWitness)?,
                );
            }
            let source = sources
                .get(&vote.data.chunk_id)
                .ok_or(ProofError::InvalidWitness)?;
            records.insert(
                neutrin0_prover_chunk::consensus::verify_participation_vote_using(
                    self.consensus_domain(),
                    incoming,
                    &source.chunk,
                    &source.validators,
                    vote,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .map_err(|_| ProofError::InvalidWitness)?,
            );
        }
        if records.len() > neutrin0_consensus_types::participation::MAX_PARTICIPATION_ACKS {
            return Err(ProofError::InvalidWitness.into());
        }
        Ok(records.into_iter().collect())
    }

    /// Publish locally available omitted votes during the bounded challenge window.
    /// Individual signatures and attestations survive extraction from aggregates.
    pub(crate) fn append_participation_votes(
        &self,
        height: u64,
        body: &mut neutrin0_consensus_types::Body,
        executor: &dyn neutrin0_proof_system::ErasedBlockExecutor,
        state: &neutrin0_trie::Trie<neutrin0_trie::Poseidon2Hasher>,
    ) -> Result<(), String> {
        let incoming = self
            .chunk_of_height(height)
            .ok_or("invalid participation height")?;
        let inherited = self
            .inherited_vote_lane(height, self.head_hash())
            .map_err(|_| "participation ancestry unavailable")?;
        let mut already: alloc::collections::BTreeSet<_> = self
            .participation_acknowledgements(height, body)
            .map_err(|_| "invalid supplied participation votes")?
            .into_iter()
            .collect();
        let candidates = self.omitted_precommit_candidates(incoming, body, &inherited, &already)?;
        let runtime = self
            .runtime_code_hash_for(height)
            .map_err(|_| "participation runtime unavailable")?;
        let selected = uncovered_votes(executor, runtime, state, candidates, &mut already)?;
        admit_participation_votes(body, selected, inherited.bytes)
    }

    /// Retained individually signed precommits of the challenge window whose
    /// signer the carried certificate left out, keyed by the acknowledgement
    /// each would make, in canonical selection order.
    fn omitted_precommit_candidates(
        &self,
        incoming: u64,
        body: &neutrin0_consensus_types::Body,
        inherited: &InheritedVotes,
        already: &alloc::collections::BTreeSet<
            neutrin0_consensus_types::participation::ParticipationAcknowledgement,
        >,
    ) -> Result<
        BTreeMap<
            neutrin0_consensus_types::participation::ParticipationAcknowledgement,
            neutrin0_consensus_types::participation::ParticipationVote,
        >,
        String,
    > {
        use neutrin0_consensus_types::participation::PARTICIPATION_CHALLENGE_CHUNKS;
        let mut candidates = BTreeMap::new();
        for chunk in incoming.saturating_sub(PARTICIPATION_CHALLENGE_CHUNKS)..incoming {
            self.omitted_precommits_of(incoming, chunk, body, inherited, already, &mut candidates)?;
        }
        Ok(candidates)
    }

    /// The retained individually signed precommits for source `chunk` whose
    /// signer the carried certificate left out, added to `candidates`.
    fn omitted_precommits_of(
        &self,
        incoming: u64,
        chunk: u64,
        body: &neutrin0_consensus_types::Body,
        inherited: &InheritedVotes,
        already: &alloc::collections::BTreeSet<
            neutrin0_consensus_types::participation::ParticipationAcknowledgement,
        >,
        candidates: &mut BTreeMap<
            neutrin0_consensus_types::participation::ParticipationAcknowledgement,
            neutrin0_consensus_types::participation::ParticipationVote,
        >,
    ) -> Result<(), String> {
        use neutrin0_consensus_types::participation::ParticipationVote;
        use neutrin0_consensus_types::{
            FinalityVotePhase,
            signed_artifacts::{SignedArtifact, SignedArtifactKind},
        };
        let source = self
            .execution_history_chunk(chunk, incoming)
            .map_err(|_| "participation source read failed")?
            .ok_or("participation source unavailable")?;
        let source_hash = source.chunk.hash();
        let Some(report) = self.absence_report(chunk, body, &source)? else {
            return Ok(());
        };
        for metadata in self
            .store()
            .signed_artifact_metadata_for_chunk(chunk)
            .map_err(|_| "participation inventory read failed")?
        {
            if metadata.kind != SignedArtifactKind::Vote {
                continue;
            }
            let Some((_, SignedArtifact::Vote(vote))) = self
                .store()
                .signed_artifact(&metadata.id)
                .map_err(|_| "participation vote read failed")?
            else {
                continue;
            };
            if vote.data.phase != FinalityVotePhase::Precommit
                || vote.data.chunk_hash != source_hash
            {
                continue;
            }
            for claim in &vote.attestations {
                let Some(compact) = ParticipationVote::from_attestation(claim) else {
                    continue;
                };
                let Some(record) = neutrin0_consensus_types::participation::acknowledgement_from_participation_vote(
                    incoming, source_hash, &source.validators, &compact,
                ) else { continue; };
                if !report.absent_identities.contains(&record.identity)
                    || already.contains(&record)
                    || candidates.contains_key(&record)
                    || inherited.seats.contains(&compact.source_seat())
                {
                    continue;
                }
                neutrin0_prover_chunk::consensus::verify_participation_vote_using(
                    self.consensus_domain(),
                    incoming,
                    &source.chunk,
                    &source.validators,
                    &compact,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .map_err(|_| "invalid retained individual participation vote")?;
                candidates.insert(record, compact);
            }
        }
        Ok(())
    }

    /// The participation report of source `chunk` under the certificate the
    /// following chunk carries, or `None` before one is carried.
    fn absence_report(
        &self,
        chunk: u64,
        body: &neutrin0_consensus_types::Body,
        source: &neutrin0_prover_chunk::history::HistoricalChunk,
    ) -> Result<Option<neutrin0_consensus_types::participation::ParticipationReport>, String> {
        // Absence follows the certificate the following chunk carries,
        // which may be another valid subset than this node's own: only a
        // precommit it left out needs acknowledging. Before it is carried
        // nothing can be charged, and a later block in the window acks.
        let carried = body
            .participation
            .as_ref()
            .filter(|carried| carried.quorum.data.chunk_id == chunk)
            .map_or_else(
                || {
                    self.selected_participation_certificate(chunk)
                        .ok()
                        .flatten()
                },
                |carried| Some(carried.quorum.clone()),
            );
        let Some(carried) = carried else {
            return Ok(None);
        };
        neutrin0_consensus_types::participation::ParticipationReport::from_certificate(
            chunk,
            &source.validators,
            &carried.aggregate.aggregation_bits,
        )
        .ok_or("participation certificate does not cover its committee")
        .map(Some)
        .map_err(Into::into)
    }

    /// The vote lanes of the blocks before `height` in its chunk, on the
    /// branch ending at `parent`.
    pub(super) fn inherited_vote_lane(
        &self,
        height: u64,
        mut parent: Hash,
    ) -> Result<InheritedVotes, FinalizeError<DB::Error>> {
        let chunk = self
            .chunk_of_height(height)
            .ok_or(ProofError::InvalidWitness)?;
        let start = chunk
            .checked_mul(self.chunk_size())
            .and_then(|height| height.checked_add(1))
            .ok_or(ProofError::InvalidWitness)?;
        let mut inherited = InheritedVotes::default();
        for expected in (start..height).rev() {
            let block = self
                .store()
                .get_block(&parent)?
                .ok_or(ProofError::InvalidWitness)?;
            if block.header.height != expected {
                return Err(ProofError::InvalidWitness.into());
            }
            inherited.bytes = inherited
                .bytes
                .checked_add(neutrin0_consensus_types::participation::vote_lane_bytes(
                    &block.body.participation_acks,
                )?)
                .ok_or(ProofError::InvalidWitness)?;
            inherited.seats.extend(
                block
                    .body
                    .participation_acks
                    .iter()
                    .map(neutrin0_consensus_types::participation::ParticipationVote::source_seat),
            );
            parent = block.header.parent_hash;
        }
        Ok(inherited)
    }
}

#[cfg(test)]
mod compact_ack_admission_tests;
