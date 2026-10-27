//! Retained chunk proofs, certificates and the History proof of the local endpoint.

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::history_proof::Checkpoint;
use neutrin0_network::rpc::{
    self, ChunkProofByIdResponse, FinalityCertByChunkResponse, HistoryProofResponse,
};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{ChainBackend, bounded, check_count, not_available, storage_error};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    fn ensure_retained_chunk(engine: &Engine<DB>, id: ChunkId) -> Result<(), SyncBackendError> {
        let retention = engine.retention_info().map_err(storage_error)?;
        if id < retention.pruned_before_chunk {
            return Err(SyncBackendError::Pruned {
                retained_from_chunk: retention.pruned_before_chunk,
                retained_from_height: retention.first_retained_height,
            });
        }
        Ok(())
    }

    pub(in crate::chain_backend) fn p2p_chunk_proofs_by_id(
        &self,
        ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        check_count(ids.len(), rpc::MAX_CHUNK_PROOFS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let proofs = ids
                .iter()
                .map(|id| {
                    Self::ensure_retained_chunk(engine, *id)?;
                    let proof = engine
                        .store()
                        .get_chunk_proof(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| not_available("chunk proof is unavailable"))?;
                    let chunk = engine
                        .store()
                        .get_chunk(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| storage_error("chunk proof has no stored chunk"))?;
                    if proof.chunk_id != *id
                        || proof.public_inputs.chunk_id != *id
                        || proof.chunk_hash != chunk.hash()
                        || proof.finality_cert.chunk_id != *id
                        || proof.finality_cert.chunk_hash != proof.chunk_hash
                    {
                        return Err(storage_error("chunk proof envelope is inconsistent"));
                    }
                    Ok(proof)
                })
                .collect::<Result<_, _>>()?;
            Ok::<_, SyncBackendError>(ChunkProofByIdResponse { proofs })
        })
        .and_then(bounded)
    }

    /// The retained proof of each chunk with the named statement key,
    /// canonical or alternative (design 08); unknown entries are omitted.
    pub(in crate::chain_backend) fn p2p_chunk_proofs_by_key(
        &self,
        entries: &[(ChunkId, Hash)],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        check_count(entries.len(), rpc::MAX_CHUNK_PROOFS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let mut proofs = Vec::new();
            for (id, key) in entries {
                Self::ensure_retained_chunk(engine, *id)?;
                if let Some(held) = engine
                    .store()
                    .chunk_receipts(*id)
                    .map_err(storage_error)?
                    .into_iter()
                    .find(|held| held.statement_key == *key)
                {
                    proofs.push(held.proof);
                }
            }
            Ok::<_, SyncBackendError>(ChunkProofByIdResponse { proofs })
        })
        .and_then(bounded)
    }

    /// The History proof of the canonical endpoint at `end` chunks, pinned by
    /// its checkpoint hash, with the opening of the boundary at `anchor`
    /// chunks under it. A requester anchored anywhere but the specification's
    /// start or the endpoint itself needs that opening to advance, so without
    /// one the request is unavailable here. A light node serves only its own
    /// latest proof and opens nothing.
    pub(in crate::chain_backend) fn p2p_history_proof(
        &self,
        anchor: u64,
        end: u64,
        checkpoint: Hash,
    ) -> Result<HistoryProofResponse, SyncBackendError> {
        let first = self.with_engine(|engine| engine.chain_spec().first_chunk());
        let needs_opening =
            neutrin0_consensus_types::history_proof::needs_opening(first, anchor, end);
        if self.is_light() {
            if needs_opening {
                return Err(not_available("a light node opens no anchor"));
            }
            let proof = self
                .light_latest_proof()
                .map_err(storage_error)?
                .filter(|proof| {
                    proof.end().next_chunk_id == end && proof.end_checkpoint().hash() == checkpoint
                })
                .ok_or_else(|| not_available("History proof not retained"))?;
            return Ok(HistoryProofResponse {
                proof,
                anchor: None,
                bootstrap: None,
            });
        }
        let response = self.with_engine(|engine| {
            let id = end
                .checked_sub(1)
                .ok_or_else(|| not_available("genesis has no History proof"))?;
            Self::ensure_retained_chunk(engine, id)?;
            let boundary = engine
                .canonical_boundary(end)
                .map_err(|_| not_available("History endpoint is not finalized here"))?;
            let chain = engine
                .store()
                .history_domain()
                .map_err(storage_error)?
                .ok_or_else(|| not_available("History proofs are not initialized"))?
                .chain;
            if (Checkpoint { chain, boundary }).hash() != checkpoint {
                return Err(not_available(
                    "History endpoint differs from the local chain",
                ));
            }
            let proof = engine
                .history_proof(end)
                .map_err(storage_error)?
                .ok_or_else(|| not_available("History proof not retained"))?;
            let anchor = engine.anchor_opening(anchor, end).ok().flatten();
            if needs_opening && anchor.is_none() {
                return Err(not_available("anchor opening not retained"));
            }
            Ok(HistoryProofResponse {
                proof,
                anchor,
                bootstrap: None,
            })
        })?;
        bounded(response)
    }

    pub(in crate::chain_backend) fn p2p_finality_certs_by_chunk(
        &self,
        ids: &[ChunkId],
    ) -> Result<FinalityCertByChunkResponse, SyncBackendError> {
        check_count(ids.len(), rpc::MAX_FINALITY_CERTS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let certs = ids
                .iter()
                .map(|id| {
                    if let Some(witness) = engine.certified_execution_witness()
                        && witness.context.chunk_id == *id
                    {
                        return Ok(witness.finality_cert.clone());
                    }
                    Self::ensure_retained_chunk(engine, *id)?;
                    let cert = engine
                        .store()
                        .get_finality_cert(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| not_available("finality certificate is unavailable"))?;
                    let chunk = engine
                        .store()
                        .get_chunk(*id)
                        .map_err(storage_error)?
                        .ok_or_else(|| storage_error("certificate has no stored chunk"))?;
                    if cert.chunk_id != *id || cert.chunk_hash != chunk.hash() {
                        return Err(storage_error(
                            "finality certificate envelope is inconsistent",
                        ));
                    }
                    Ok(cert)
                })
                .collect::<Result<_, _>>()?;
            Ok::<_, SyncBackendError>(FinalityCertByChunkResponse { certs })
        })
        .and_then(bounded)
    }
}
