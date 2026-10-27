//! Detecting abandoned heights: observed signed blocks the canonical chain
//! replaced after their exclusive proof window (design 08).

use neutrin0_consensus_types::Header;
use neutrin0_consensus_types::evidence::{EvidenceArtifact, MerkleOpening};
use neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_prover_chunk::evidence::{EvidenceClaim, EvidenceWitness};
use neutrin0_prover_chunk::history::{HistoricalChunk, PENALTY_ABANDONMENT, penalty_id};
use neutrin0_runtime_abi::operational::{EvidenceCoverageRequest, EvidencePolicy};
use neutrin0_storage::Database;

use super::ChainBackend;
use super::policy::coverage;

type Engine<DB> = neutrin0_consensus_engine::Engine<DB>;

/// Witnesses one selection pass may hold in all, as for inactivity.
const MAX_WITNESSES: usize = 16;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Abandoned heights in the retained window's finalized chunks, from the
    /// signed headers the slashing monitor observed, up to sixteen witnesses
    /// in all.
    pub(super) fn abandonment_jobs(
        &self,
        engine: &Engine<DB>,
        executor: &dyn ErasedBlockExecutor,
        policy: &EvidencePolicy,
        existing: &[EvidenceArtifact],
        block_key: [u32; 8],
        witnesses: &mut Vec<EvidenceWitness>,
    ) {
        if policy.abandonment_penalty_amount == 0 {
            return;
        }
        let known = |id: &Hash| {
            existing.iter().any(|item| item.statement.offence_id == *id)
                || coverage(
                    engine,
                    executor,
                    &EvidenceCoverageRequest {
                        identity: [0; 48],
                        offence_id: Some(*id),
                        liveness: None,
                    },
                )
                .is_none_or(|status| status.admitted)
        };
        let window = engine.chain_spec().consensus.proof_exclusive_slots;
        let next_chunk = engine.finalized_next_chunk_id();
        for chunk_id in next_chunk.saturating_sub(HISTORY_RETENTION_CHUNKS)..next_chunk {
            let observed = engine.observed_headers(chunk_id).unwrap_or_default();
            if observed.is_empty() {
                continue;
            }
            let Ok(Some(source)) = engine.store().historical_chunk(chunk_id) else {
                continue;
            };
            if engine
                .head_height()
                .saturating_add(1)
                .saturating_sub(source.chunk.end_height)
                > policy.evidence_max_age_blocks
            {
                continue;
            }
            let Some((canonical, hashes)) = canonical_headers(engine, &source) else {
                continue;
            };
            for abandoned in observed {
                if witnesses.len() >= MAX_WITNESSES {
                    return;
                }
                let Some(index) = abandoned
                    .height
                    .checked_sub(source.chunk.start_height)
                    .and_then(|index| usize::try_from(index).ok())
                    .filter(|index| *index < canonical.len())
                else {
                    continue;
                };
                let replacement = &canonical[index];
                let replaced_late = abandoned
                    .slot
                    .checked_add(window)
                    .is_some_and(|deadline| replacement.slot >= deadline);
                if abandoned.parent_hash != replacement.parent_hash
                    || hashes[index] == abandoned.hash()
                    || !replaced_late
                {
                    continue;
                }
                let Some(validator) = source
                    .validators
                    .get(abandoned.proposer_index as usize)
                    .filter(|validator| validator.effective_stake > 0)
                else {
                    continue;
                };
                if known(&penalty_id(
                    PENALTY_ABANDONMENT,
                    validator,
                    abandoned.slot,
                    0,
                )) {
                    continue;
                }
                let Some(opening) = MerkleOpening::build(&hashes, index) else {
                    continue;
                };
                witnesses.push(EvidenceWitness {
                    chain_spec: engine.chain_spec().clone(),
                    source: source.clone(),
                    claim: EvidenceClaim::Abandonment {
                        abandoned,
                        canonical: replacement.clone(),
                        opening,
                    },
                    block_guest_vk_digest: block_key,
                    reporter: self.reporter_recipient(),
                });
            }
        }
    }
}

/// The finalized chunk's canonical headers in height order with their hashes,
/// if every one is retained and they reproduce its block hash root.
fn canonical_headers<DB: Database>(
    engine: &Engine<DB>,
    source: &HistoricalChunk,
) -> Option<(Vec<Header>, Vec<Hash>)> {
    let headers = (source.chunk.start_height..=source.chunk.end_height)
        .map(|height| engine.store().get_header_by_height(height).ok().flatten())
        .collect::<Option<Vec<_>>>()?;
    let hashes: Vec<Hash> = headers.iter().map(Header::hash).collect();
    (neutrin0_primitives::merkle_root_of_hashes(&hashes) == source.chunk.block_hash_root)
        .then_some((headers, hashes))
}
