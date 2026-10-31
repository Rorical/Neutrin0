//! The [`SyncBackend`] surface the sync driver and network service call;
//! every method delegates to the responsibility modules.

use std::sync::Arc;

use async_trait::async_trait;
use neutrin0_consensus_types::{
    BlockReceipt, CandidateBlock, ChunkProof, FinalityVote, HistoryProof, ProvenBlock,
    SlashingEvidence,
};
use neutrin0_network::rpc::{
    BlocksByRangeResponse, ChunkProofByIdResponse, FinalityCertByChunkResponse,
    HistoryProofResponse, Metadata, ReceiptsByHashResponse, StateByRootResponse, Status,
    WitnessByBlockResponse,
};
use neutrin0_network::sync::LocalProgress;
use neutrin0_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, StateRoot};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::{
    CheckpointsImported, ChunkProofImported, HeadersImported, ReceiptsImported, StateProgress,
    SyncBackend, SyncBackendError,
};

use super::{ChainBackend, chunk_height_range, rejected, storage_error};

#[async_trait]
impl<DB, P> SyncBackend for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn consensus_sync_target(
        &self,
    ) -> Result<Option<neutrin0_sync::backend::ConsensusSyncTarget>, SyncBackendError> {
        if self.is_light() {
            return Ok(None);
        }
        if self.block_program().is_none() {
            return Ok(None);
        }
        self.with_engine(|engine| {
            let chunk_id = engine.finalized_next_chunk_id();
            let size = engine.chain_spec().consensus.chunk_size;
            let (start_height, end_height) =
                chunk_height_range(chunk_id, size).ok_or_else(|| rejected("height overflow"))?;
            Ok(Some(neutrin0_sync::backend::ConsensusSyncTarget {
                chunk_id,
                start_height,
                end_height,
            }))
        })
    }
    fn supports_bft_candidate_sync(&self) -> bool {
        !self.is_light() && self.block_program().is_some()
    }

    fn supports_certified_execution_sync(&self) -> bool {
        self.supports_bft_candidate_sync()
    }

    async fn certified_execution_sync_height(&self) -> Option<Height> {
        self.with_engine(|engine| {
            engine.certified_execution_boundary().and_then(|boundary| {
                boundary
                    .height
                    .checked_add(engine.chain_spec().consensus.chunk_size)
            })
        })
    }

    async fn verify_and_import_execution_certificate(
        &self,
        certificate: neutrin0_consensus_types::FinalityCert,
    ) -> Result<(), SyncBackendError> {
        if !self.supports_certified_execution_sync() {
            return Err(SyncBackendError::NotAvailable(
                "execution certification is disabled".into(),
            ));
        }
        self.certify_execution_certificate(
            Some(certificate),
            None,
            Arc::clone(&self.certification_slot)
                .acquire_owned()
                .await
                .map_err(|_| {
                    SyncBackendError::NotAvailable("certification worker closed".into())
                })?,
        )
        .await?;
        self.sync_programs();
        if let Some(identity) = self.ready_consensus_quorum() {
            self.handle_quorum_reached(identity).await;
        }
        Ok(())
    }

    async fn bft_candidate(
        &self,
        chunk_id: ChunkId,
        hash: Option<Hash>,
    ) -> Result<neutrin0_network::rpc::CandidateByChunkResponse, SyncBackendError> {
        self.p2p_bft_candidate(chunk_id, hash).await
    }

    async fn validate_bft_candidate_hint(
        &self,
        candidate: &neutrin0_consensus_types::BftCandidate,
    ) -> bool {
        self.authenticated_bft_candidate_hint(candidate)
    }

    async fn bft_vote_needs_candidate(&self, vote: &FinalityVote) -> bool {
        self.authenticated_missing_bft_candidate(vote)
    }

    async fn holds_bft_candidate_branch(
        &self,
        candidate: &neutrin0_consensus_types::BftCandidate,
    ) -> bool {
        let (hash, height) = (candidate.chunk.end_block_hash, candidate.chunk.end_height);
        // A stored proven block's ancestors are stored and proven too.
        self.with_engine(|engine| {
            engine
                .store()
                .get_header(&hash)
                .ok()
                .flatten()
                .is_some_and(|header| header.height == height)
                && engine.store().get_block_state(&hash).ok().flatten()
                    == Some(neutrin0_consensus_engine::BlockState::Proven)
        })
    }

    async fn consider_bft_candidate(
        &self,
        candidate: neutrin0_consensus_types::BftCandidate,
    ) -> Result<(), SyncBackendError> {
        self.consider_downloaded_bft_candidate(&candidate).await
    }

    fn supports_bft_message_sync(&self) -> bool {
        !self.bootstrap_pending() && !self.is_light() && self.block_program().is_some()
    }

    async fn current_bft_round(&self) -> Option<(ChunkId, u32)> {
        if self.is_light() || self.bootstrap_pending() {
            return None;
        }
        Some(self.with_engine(|engine| {
            let id = engine.finalized_next_chunk_id();
            (
                id,
                engine
                    .bft_session(id)
                    .map_or(0, neutrin0_consensus_engine::BftSession::round),
            )
        }))
    }

    async fn bft_round_by_chunk(
        &self,
        id: ChunkId,
    ) -> Result<neutrin0_network::rpc::BftRoundByChunkResponse, SyncBackendError> {
        self.p2p_bft_round(id)
    }

    async fn validate_bft_proposal_hint(
        &self,
        proposal: &neutrin0_consensus_types::BftProposal,
    ) -> Result<(), SyncBackendError> {
        self.authenticated_bft_proposal_hint(proposal)
    }

    async fn ingest_bft_message(
        &self,
        message: neutrin0_consensus_types::BftMessage,
    ) -> Result<(), SyncBackendError> {
        self.accept_bft_message(message).await
    }

    fn supports_signed_artifact_sync(&self) -> bool {
        !self.bootstrap_pending() && !self.is_light()
    }

    async fn signed_artifact_source_known(&self, id: ChunkId) -> bool {
        !self.is_light() && self.availability_source_known(id)
    }

    async fn signed_artifact_matches_source(
        &self,
        artifact: &neutrin0_consensus_types::signed_artifacts::SignedArtifact,
        id: ChunkId,
    ) -> bool {
        self.with_engine(|engine| {
            artifact.chunk_id(engine.chain_spec().consensus.chunk_size) == Some(id)
        })
    }

    async fn signed_artifact_by_id(
        &self,
        id: Hash,
    ) -> Result<neutrin0_network::rpc::SignedArtifactByIdResponse, SyncBackendError> {
        self.query_signed_artifact(id)
    }

    async fn signed_artifact_inventory(
        &self,
        id: ChunkId,
        after: Option<Hash>,
    ) -> Result<neutrin0_network::rpc::SignedArtifactInventoryByChunkResponse, SyncBackendError>
    {
        self.query_signed_inventory(id, after)
    }

    async fn ingest_signed_artifact(
        &self,
        artifact: neutrin0_consensus_types::signed_artifacts::SignedArtifact,
    ) -> neutrin0_sync::EvidenceProofAcceptance {
        self.accept_signed_source(artifact).await
    }

    async fn missing_vote_artifacts(
        &self,
        vote: &FinalityVote,
    ) -> Vec<neutrin0_consensus_types::signed_artifacts::SignedArtifactRef> {
        self.missing_signed_artifacts(vote)
    }

    async fn local_status(&self) -> Result<Status, SyncBackendError> {
        self.p2p_local_status()
    }

    async fn local_metadata(&self) -> Metadata {
        self.p2p_local_metadata()
    }

    async fn local_progress(&self) -> Result<LocalProgress, SyncBackendError> {
        self.p2p_local_progress()
    }

    async fn history_proof(
        &self,
        anchor: CheckpointIndex,
        end: CheckpointIndex,
        checkpoint: Hash,
    ) -> Result<HistoryProofResponse, SyncBackendError> {
        self.p2p_history_proof(anchor, end, checkpoint)
    }

    async fn blocks_by_range(
        &self,
        start: Height,
        count: u64,
        head: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError> {
        self.p2p_blocks_by_range(start, count, head)
    }

    async fn state_nodes(
        &self,
        root: StateRoot,
        items: &[neutrin0_consensus_types::bootstrap::StateItem],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        self.p2p_state_nodes(root, items)
    }

    async fn bootstrap_origin(&self) -> Option<neutrin0_consensus_types::Checkpoint> {
        Self::bootstrap_origin(self)
    }
    async fn bootstrap_fetch(&self, active: bool) {
        Self::bootstrap_fetch(self, active);
    }

    async fn bootstrap_state(
        &self,
    ) -> Result<
        Option<(
            StateRoot,
            Vec<neutrin0_consensus_types::bootstrap::StateItem>,
        )>,
        SyncBackendError,
    > {
        Self::bootstrap_state(self)
    }
    async fn bootstrap_data(
        &self,
        end: Hash,
    ) -> Result<neutrin0_consensus_types::bootstrap::BootstrapData, SyncBackendError> {
        self.serve_bootstrap(end)
    }
    async fn restart_state_fragments(
        &self,
        items: &[neutrin0_consensus_types::bootstrap::StateItem],
    ) -> Result<(), SyncBackendError> {
        Self::restart_state_fragments(self, items)
    }
    async fn begin_bootstrap(
        &self,
        anchor: Option<neutrin0_consensus_types::AnchorOpening>,
        data: neutrin0_consensus_types::bootstrap::BootstrapData,
    ) -> Result<neutrin0_sync::StateProgress, SyncBackendError> {
        Self::begin_bootstrap(self, anchor, data).await
    }

    async fn chunk_proofs_by_id(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        self.p2p_chunk_proofs_by_id(chunk_ids)
    }

    async fn chunk_proofs_by_key(
        &self,
        entries: &[(ChunkId, Hash)],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        self.p2p_chunk_proofs_by_key(entries)
    }

    async fn missing_proposal_artifacts(
        &self,
        proposal: &neutrin0_consensus_types::BftProposal,
    ) -> neutrin0_sync::ProposalArtifacts {
        self.with_engine(|engine| {
            engine
                .missing_proposal_artifacts(proposal)
                .map(
                    |(receipts, chunk_proofs)| neutrin0_sync::ProposalArtifacts {
                        receipts,
                        chunk_proofs,
                    },
                )
                .unwrap_or_default()
        })
    }

    async fn finality_certs_by_chunk(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<FinalityCertByChunkResponse, SyncBackendError> {
        self.p2p_finality_certs_by_chunk(chunk_ids)
    }

    async fn witnesses_by_block(
        &self,
        block_hashes: &[BlockHash],
    ) -> Result<WitnessByBlockResponse, SyncBackendError> {
        self.p2p_witnesses_by_block(block_hashes)
    }

    async fn verify_and_import_history(
        &self,
        proof: HistoryProof,
        anchor: Option<neutrin0_consensus_types::AnchorOpening>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        // Full nodes finalize every chunk themselves; their latest chunk
        // receipt already is their History proof.
        if !self.is_light() {
            return Err(SyncBackendError::NotAvailable(
                "only light clients import History proofs".into(),
            ));
        }
        let metric_timer = self.metrics.execution.history_verification.timer();
        let result = self.accept_light_history(proof, anchor).await;
        metric_timer.finish(result.is_ok());
        result
    }

    async fn verify_history_conflict(&self, proof: HistoryProof) -> Result<bool, SyncBackendError> {
        if !self.is_light() {
            return Err(SyncBackendError::NotAvailable(
                "only light clients check History conflicts".into(),
            ));
        }
        self.check_light_conflict(proof).await
    }

    async fn history_halted(&self) -> bool {
        self.light_halted()
    }

    async fn verify_and_import_proven_blocks(
        &self,
        blocks: Vec<ProvenBlock>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.block_imports.timer();
        self.ensure_full_import()?;
        if let Some(bundle) = blocks.iter().find(|bundle| !bundle.writes_well_formed()) {
            return Err(SyncBackendError::Rejected(format!(
                "block {} carries a non-canonical write set",
                bundle.block.header.height
            )));
        }
        let result = self.import_proven_blocks(blocks).await;
        metric_timer.finish(result.is_ok());
        result
    }

    async fn verify_and_import_candidates(
        &self,
        candidates: Vec<CandidateBlock>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.block_imports.timer();
        self.ensure_full_import()?;
        // Candidates are unfinalized data; ignored (never penalized) while
        // the data filesystem is below its quota.
        if self.storage_pressure() {
            return Err(SyncBackendError::NotAvailable(
                "storage pressure: new candidates are not stored".into(),
            ));
        }
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| !candidate.writes_well_formed())
        {
            return Err(SyncBackendError::Rejected(format!(
                "candidate {} carries a non-canonical write set",
                candidate.block.header.height
            )));
        }
        let result = self.import_candidates(candidates).await;
        metric_timer.finish(result.is_ok());
        result
    }

    async fn verify_and_import_receipts(
        &self,
        receipts: Vec<BlockReceipt>,
        source: neutrin0_network::PeerId,
    ) -> Result<ReceiptsImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.block_verification.timer();
        self.ensure_full_import()?;
        let result = self.import_receipts(receipts, source).await;
        metric_timer.finish(result.is_ok());
        result
    }

    async fn receipts_by_hash(
        &self,
        block_hashes: &[BlockHash],
    ) -> Result<ReceiptsByHashResponse, SyncBackendError> {
        self.p2p_receipts_by_hash(block_hashes)
    }

    async fn wanted_program_fragment(
        &self,
    ) -> Option<neutrin0_consensus_types::bootstrap::StateItem> {
        // Light clients run no programs; a bootstrapping node's snapshot
        // journal fetches the programs its endpoint needs.
        self.ensure_full_import().ok()?;
        self.next_program_fetch()
    }

    async fn import_program_fragment(
        &self,
        entry: neutrin0_consensus_types::bootstrap::StateEntry,
    ) -> bool {
        self.absorb_fetched_fragment(&entry)
    }

    async fn dormant_reporter_path(&self) -> Option<neutrin0_network::rpc::HistoryProofRequest> {
        self.ensure_full_import().ok()?;
        self.with_engine(|engine| {
            let dormant = engine.reporter_dormant_chunks().ok()?;
            // Rotate over time so one path no provider can open never starves the rest.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            let len = u64::try_from(dormant.len()).ok()?;
            let anchor =
                *dormant.get(usize::try_from(now.checked_div(30)?.checked_rem(len)?).ok()?)?;
            let end = engine.finalized_next_chunk_id();
            let chain = engine.store().history_domain().ok().flatten()?.chain;
            let boundary = engine.canonical_boundary(end).ok()?;
            Some(neutrin0_network::rpc::HistoryProofRequest {
                anchor_chunks: anchor,
                end_chunks: end,
                checkpoint_hash: neutrin0_consensus_types::Checkpoint { chain, boundary }.hash(),
                bootstrap: false,
            })
        })
    }

    async fn refresh_reporter_path(
        &self,
        opening: neutrin0_consensus_types::AnchorOpening,
    ) -> bool {
        self.with_engine_mut(|engine| engine.refresh_reporter_path(&opening))
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "reporter path refresh failed");
                false
            })
    }

    async fn import_state_nodes(
        &self,
        root: StateRoot,
        items: Vec<neutrin0_consensus_types::bootstrap::StateItem>,
        entries: Vec<neutrin0_consensus_types::bootstrap::StateEntry>,
    ) -> Result<StateProgress, SyncBackendError> {
        self.reject_light()?;
        let pending = self.bootstrap_state()?;
        if pending
            .as_ref()
            .is_some_and(|(expected, _)| *expected != root)
        {
            return Err(SyncBackendError::Rejected(
                "state response targets another bootstrap".into(),
            ));
        }
        let progress = self.receive_state_entries(root, &items, &entries)?;
        self.authenticate_received_guests(root, &items).await?;
        if progress.root_complete {
            if pending.is_some() {
                if self.bootstrap_downloads_complete()? {
                    self.finish_bootstrap().await?;
                } else {
                    // The other independently authenticated trie is still
                    // pending. The driver asks bootstrap_state for its root.
                    return Ok(StateProgress {
                        root_complete: false,
                        next_items: Vec::new(),
                    });
                }
            } else {
                self.install_downloaded_state(&[root])?;
                // A head that moved past the snapshot keeps nothing of it.
                self.with_live_engine_mut(|engine| {
                    engine
                        .adopt_installed_head_state()
                        .map(|_| ())
                        .map_err(storage_error)
                })?;
                self.clear_state_download(root)?;
            }
        }
        Ok(progress)
    }

    fn supports_transaction_sync(&self) -> bool {
        !self.is_light()
    }

    async fn transaction_inventory(&self, after: Option<Hash>) -> Vec<Hash> {
        if self.is_light() {
            return Vec::new();
        }
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.expire(crate::now_secs(), 15 * 60);
        let mut hashes: Vec<_> = pool
            .iter()
            .map(|entry| entry.hash)
            .filter(|hash| after.is_none_or(|cursor| *hash > cursor))
            .collect();
        drop(pool);
        hashes.sort_unstable();
        hashes.truncate(neutrin0_network::rpc::MAX_TRANSACTION_INVENTORY);
        hashes
    }

    async fn pending_transactions(&self, hashes: &[Hash]) -> Vec<Vec<u8>> {
        if self.is_light() {
            return Vec::new();
        }
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.expire(crate::now_secs(), 15 * 60);
        let transactions = hashes
            .iter()
            .take(neutrin0_network::rpc::MAX_TRANSACTIONS_PER_REQUEST)
            .filter_map(|hash| {
                pool.iter()
                    .find(|entry| entry.hash == *hash)
                    .map(|entry| entry.bytes.clone())
            })
            .filter(|bytes| bytes.len() <= neutrin0_network::rpc::MAX_TRANSACTION_BYTES)
            .collect();
        drop(pool);
        transactions
    }

    async fn missing_transactions(&self, hashes: &[Hash]) -> Vec<Hash> {
        let mut pool = self.mempool.lock().expect("ChainBackend mempool poisoned");
        pool.expire(crate::now_secs(), 15 * 60);
        let missing = hashes
            .iter()
            .copied()
            .filter(|hash| !pool.contains(hash))
            .collect();
        drop(pool);
        missing
    }

    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<(), SyncBackendError> {
        self.admit_peer_transaction(bytes, None).await
    }

    async fn submit_transaction_in_runtime(
        &self,
        runtime: Hash,
        bytes: Vec<u8>,
    ) -> Result<(), SyncBackendError> {
        self.admit_peer_transaction(bytes, Some(runtime)).await
    }

    async fn verify_and_import_chunk_proof(
        &self,
        proof: ChunkProof,
        source: neutrin0_network::PeerId,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        self.accept_chunk_proof(proof, source).await
    }

    async fn ingest_finality_vote(&self, vote: FinalityVote) -> Result<(), SyncBackendError> {
        self.ingest_value_vote(vote, None).await
    }

    async fn ingest_aggregate_finality_vote(
        &self,
        subnet: u8,
        vote: FinalityVote,
    ) -> Result<(), SyncBackendError> {
        self.ingest_value_vote(vote, Some(subnet)).await
    }

    async fn ingest_evidence_proof(
        &self,
        report: neutrin0_consensus_types::evidence::EvidenceReport,
    ) -> neutrin0_sync::EvidenceProofAcceptance {
        if self.is_light() {
            return neutrin0_sync::EvidenceProofAcceptance::Deferred;
        }
        self.accept_evidence_report(report).await
    }

    async fn ingest_slashing_evidence(
        &self,
        evidence: SlashingEvidence,
    ) -> Result<(), SyncBackendError> {
        self.accept_slashing_evidence(evidence).await
    }
}
