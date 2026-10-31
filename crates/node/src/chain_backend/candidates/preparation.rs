//! Short engine reads select the exact branch advertised by a candidate query.

use super::{BftCandidate, ChunkId, Database, Hash, SyncBackendError, not_available};
use neutrin0_consensus_engine::{Engine, full_chunk::PendingConsensusChunk};
use neutrin0_prover_chunk::consensus::ConsensusWitness;

pub(super) struct CandidateInputs {
    pub(super) pending: PendingConsensusChunk,
    pub(super) candidate: Option<BftCandidate>,
    pub(super) certified: Option<ConsensusWitness>,
}

pub(super) fn capture<DB: Database>(
    engine: &Engine<DB>,
    id: ChunkId,
    hash: Option<Hash>,
) -> Result<CandidateInputs, SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    if id != engine.finalized_next_chunk_id() {
        return Err(SyncBackendError::NotAvailable(
            "candidate is outside the next chunk".into(),
        ));
    }
    let certified = engine
        .certified_execution_witness()
        .filter(|witness| {
            witness.finality_cert.chunk_id == id
                && hash.is_none_or(|hash| witness.finality_cert.chunk_hash == hash)
        })
        .cloned();
    let candidate = selected_candidate(engine, id, hash, certified.as_ref());
    let end_hash = if let Some(candidate) = &candidate {
        candidate.chunk.end_block_hash
    } else {
        let (_, end) = engine
            .chunk_heights(id)
            .ok_or_else(|| not_available("chunk height overflow"))?;
        engine
            .store()
            .get_block_hash_by_height(end)
            .map_err(not_available)?
            .ok_or_else(|| not_available("chunk end unavailable"))?
    };
    let keys = certified
        .as_ref()
        .map(|witness| witness.finality_cert.proposal.receipt_keys());
    let pending = engine
        .pending_consensus_chunk(id, end_hash, keys.as_deref())
        .map_err(not_available)?;
    Ok(CandidateInputs {
        pending,
        candidate,
        certified,
    })
}

fn selected_candidate<DB: Database>(
    engine: &Engine<DB>,
    id: ChunkId,
    hash: Option<Hash>,
    certified: Option<&ConsensusWitness>,
) -> Option<BftCandidate> {
    if let Some(witness) = certified {
        let proposal = &witness.finality_cert.proposal;
        return Some(BftCandidate {
            chunk: proposal.chunk.clone(),
            round: proposal.round,
            justification: proposal.valid_quorum.clone(),
            selection: proposal
                .valid_quorum
                .is_some()
                .then(|| proposal.payment_selection()),
        });
    }
    engine
        .bft_candidate(id)
        .filter(|candidate| hash.is_none_or(|hash| candidate.chunk.hash() == hash))
        .or_else(|| {
            hash.and_then(|hash| engine.bft_session(id)?.candidate_by_hash(&hash).cloned())
                .map(|chunk| BftCandidate {
                    chunk,
                    round: 0,
                    justification: None,
                    selection: None,
                })
        })
}
