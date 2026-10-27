//! End-to-end driver loop tests.
//!
//! These tests stand up the [`SyncDriver`] against a deterministic in-memory
//! [`SyncBackend`] and assert that:
//!
//! - inbound `NetworkEvent`s are translated into the expected sync FSM
//!   transitions, and
//! - outbound [`NetworkCommand`]s appear on the command channel in the
//!   order the FSM emits them.
//!
//! No libp2p is involved; the harness pretends to be the network service.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use neutrin0_consensus_types::{
    Block, BlockProof, ChunkProof, FinalityVote, HistoryProof, SlashingEvidence,
    bootstrap::{BootstrapData, StateEntries, StateItem},
    history_proof::Checkpoint,
};
use neutrin0_network::PeerId;
use neutrin0_network::libp2p::identity::Keypair;
use neutrin0_network::rpc::{
    BlocksByRangeResponse, ChunkProofByIdResponse, HistoryProofResponse, MetadataRequest,
    RpcInboundId, RpcProtocol, RpcRequest, RpcResponse, StateByRootResponse, Status, role_flags,
};
use neutrin0_network::service::{NetworkCommand, NetworkEvent};
use neutrin0_network::sync::LocalProgress;
use neutrin0_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, StateRoot};
use neutrin0_sync::{
    CheckpointsImported, ChunkProofImported, HeadersImported, StateProgress, SyncBackend,
    SyncBackendError, SyncDriver, SyncDriverConfig,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent transport/fault switches in the fixture.
struct MockState {
    proven_bundle_heights: Vec<Height>,
    full_chunk_size: Option<u64>,
    candidate_sync: bool,
    certified_sync: bool,
    certified_sync_height: Option<Height>,
    execution_certificates: Vec<neutrin0_consensus_types::FinalityCert>,
    transaction_sync: bool,
    admitted_transactions: Vec<Vec<u8>>,
    admission_error: Option<SyncBackendError>,
    bft_sync: bool,
    bft_round: u32,
    bft_branch_ready: bool,
    /// Blocks whose receipt a deferred proposal names and this node lacks;
    /// importing one of them makes the proposal's branch ready.
    missing_receipts: Vec<BlockHash>,
    bft_messages: Vec<neutrin0_consensus_types::BftMessage>,
    candidate_replacements: Vec<neutrin0_consensus_types::BftCandidate>,
    held_candidate_branch: bool,
    bootstrap_origin: Option<Checkpoint>,
    bootstrap_pending: Option<(StateRoot, Vec<StateItem>)>,
    bootstrap_endpoint: Option<Checkpoint>,
    bootstrap_imports: usize,
    bootstrap_fetching: bool,
    state_fragments: Vec<StateItem>,
    /// Scripted replies to state imports before the one that installs.
    state_progress: Vec<StateProgress>,
    /// Batches of partly received objects restarted from byte zero.
    state_restarts: Vec<Vec<StateItem>>,
    proven_height: u64,
    status: Status,
    /// Explicit ordinary-head fixture, independent of candidate availability.
    local_progress_override: Option<LocalProgress>,
    local_progress_error: bool,
    rpc_calls: Vec<String>,
    /// Endpoints of verified conflict sides; two distinct ones halt.
    conflict_endpoints: std::collections::BTreeSet<neutrin0_primitives::Hash>,
    advance_to_index: CheckpointIndex,
    advance_to_height: Height,
    chunk_proof_imports: Vec<ChunkId>,
    finality_vote_count: u32,
    aggregate_finality_vote_count: u32,
    slashing_evidence_count: u32,
    evidence_reports: Vec<neutrin0_consensus_types::evidence::EvidenceReport>,
    availability_enabled: bool,
    availability_deferred: bool,
    availability_sources: Vec<neutrin0_consensus_types::signed_artifacts::SignedArtifact>,
    availability_missing: Vec<neutrin0_consensus_types::signed_artifacts::SignedArtifactRef>,
    /// Heights for which a publication has been imported via
    /// `verify_and_import_proven_blocks`.
    imported_block_heights: std::collections::BTreeSet<Height>,
    /// Cumulative count of publication batches successfully imported.
    proofs_imported_count: u32,
    /// Transport fixture for an ahead block whose dependencies are unavailable.
    gossip_chain_behind: bool,
    /// Heights of candidates imported via `verify_and_import_candidates`.
    candidate_heights: Vec<Height>,
    /// Block hashes of receipts handed to `verify_and_import_receipts`.
    receipt_hashes: Vec<neutrin0_primitives::BlockHash>,
    /// Whether the mock keeps receipts for the orphan window.
    receipts_buffer: bool,
    /// Whether the mock rejects receipts.
    receipts_reject: bool,
    /// Range queries wait for `range_gate` before answering.
    slow_ranges: bool,
    /// Program fragment the backend keeps asking for; it accepts every
    /// fragment but never the assembly, as if its bytes failed their identity.
    wanted_program: Option<StateItem>,
}

/// Permits releasing slow range queries; none until a test adds them.
#[derive(Clone)]
struct RangeGate(Arc<tokio::sync::Semaphore>);

impl Default for RangeGate {
    fn default() -> Self {
        Self(Arc::new(tokio::sync::Semaphore::new(0)))
    }
}

#[derive(Clone, Default)]
struct MockBackend {
    range_gate: RangeGate,
    candidate_notified: Arc<tokio::sync::Notify>,
    proofs_notified: Arc<tokio::sync::Notify>,
    bft_notified: Arc<tokio::sync::Notify>,
    availability_notified: Arc<tokio::sync::Notify>,
    inner: Arc<Mutex<MockState>>,
}

impl MockBackend {
    fn set_status(&self, status: Status) {
        self.inner.lock().unwrap().status = status;
    }

    fn set_advance(&self, index: CheckpointIndex, height: Height) {
        let mut state = self.inner.lock().unwrap();
        state.advance_to_index = index;
        state.advance_to_height = height;
    }

    fn rpc_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().rpc_calls.clone()
    }

    fn chunk_proof_imports(&self) -> Vec<ChunkId> {
        self.inner.lock().unwrap().chunk_proof_imports.clone()
    }

    fn finality_vote_count(&self) -> u32 {
        self.inner.lock().unwrap().finality_vote_count
    }

    fn aggregate_finality_vote_count(&self) -> u32 {
        self.inner.lock().unwrap().aggregate_finality_vote_count
    }

    fn slashing_evidence_count(&self) -> u32 {
        self.inner.lock().unwrap().slashing_evidence_count
    }

    fn proofs_imported_count(&self) -> u32 {
        self.inner.lock().unwrap().proofs_imported_count
    }

    fn proven_bundle_heights(&self) -> Vec<Height> {
        self.inner.lock().unwrap().proven_bundle_heights.clone()
    }

    fn candidate_heights(&self) -> Vec<Height> {
        self.inner.lock().unwrap().candidate_heights.clone()
    }

    fn receipt_hashes(&self) -> Vec<neutrin0_primitives::BlockHash> {
        self.inner.lock().unwrap().receipt_hashes.clone()
    }

    fn set_receipt_disposition(&self, buffer: bool, reject: bool) {
        let mut state = self.inner.lock().unwrap();
        state.receipts_buffer = buffer;
        state.receipts_reject = reject;
    }
}

#[async_trait]
impl SyncBackend for MockBackend {
    fn supports_transaction_sync(&self) -> bool {
        self.inner.lock().unwrap().transaction_sync
    }
    async fn wanted_program_fragment(&self) -> Option<StateItem> {
        self.inner.lock().unwrap().wanted_program
    }

    async fn import_program_fragment(
        &self,
        _entry: neutrin0_consensus_types::bootstrap::StateEntry,
    ) -> bool {
        true
    }

    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<(), SyncBackendError> {
        let admission_error = self.inner.lock().unwrap().admission_error.clone();
        if let Some(error) = admission_error {
            return Err(error);
        }
        self.inner.lock().unwrap().admitted_transactions.push(bytes);
        Ok(())
    }

    fn supports_certified_execution_sync(&self) -> bool {
        self.inner.lock().unwrap().certified_sync
    }
    async fn certified_execution_sync_height(&self) -> Option<Height> {
        self.inner.lock().unwrap().certified_sync_height
    }
    async fn verify_and_import_execution_certificate(
        &self,
        certificate: neutrin0_consensus_types::FinalityCert,
    ) -> Result<(), SyncBackendError> {
        let mut state = self.inner.lock().unwrap();
        state.certified_sync_height =
            Some(certificate.proposal.chunk.end_height + state.full_chunk_size.unwrap());
        state.execution_certificates.push(certificate);
        drop(state);
        Ok(())
    }
    fn supports_bft_candidate_sync(&self) -> bool {
        self.inner.lock().unwrap().candidate_sync
    }
    async fn validate_bft_candidate_hint(
        &self,
        candidate: &neutrin0_consensus_types::BftCandidate,
    ) -> bool {
        candidate.round <= 16
            && candidate
                .justification
                .as_ref()
                .is_none_or(|qc| qc.aggregate.signature[0] == 77)
    }
    async fn bft_vote_needs_candidate(&self, _vote: &FinalityVote) -> bool {
        self.inner.lock().unwrap().candidate_sync
    }
    async fn holds_bft_candidate_branch(
        &self,
        _candidate: &neutrin0_consensus_types::BftCandidate,
    ) -> bool {
        self.inner.lock().unwrap().held_candidate_branch
    }
    async fn consider_bft_candidate(
        &self,
        candidate: neutrin0_consensus_types::BftCandidate,
    ) -> Result<(), SyncBackendError> {
        self.inner
            .lock()
            .unwrap()
            .candidate_replacements
            .push(candidate);
        self.inner.lock().unwrap().bft_branch_ready = true;
        self.candidate_notified.notify_one();
        Ok(())
    }
    fn supports_bft_message_sync(&self) -> bool {
        self.inner.lock().unwrap().bft_sync
    }
    async fn current_bft_round(&self) -> Option<(ChunkId, u32)> {
        let state = self.inner.lock().unwrap();
        state.bft_sync.then_some((0, state.bft_round))
    }
    async fn validate_bft_proposal_hint(
        &self,
        proposal: &neutrin0_consensus_types::BftProposal,
    ) -> Result<(), SyncBackendError> {
        // Transport-only marker. Engine and Guest tests verify actual BLS.
        if proposal.chunk.chunk_id != 0 {
            Err(SyncBackendError::NotAvailable("proposal source".into()))
        } else if proposal.signature[0] == 88 {
            Ok(())
        } else {
            Err(SyncBackendError::Rejected("proposal signature".into()))
        }
    }
    async fn missing_proposal_artifacts(
        &self,
        _proposal: &neutrin0_consensus_types::BftProposal,
    ) -> neutrin0_sync::ProposalArtifacts {
        neutrin0_sync::ProposalArtifacts {
            receipts: self.inner.lock().unwrap().missing_receipts.clone(),
            chunk_proofs: Vec::new(),
        }
    }

    async fn ingest_bft_message(
        &self,
        message: neutrin0_consensus_types::BftMessage,
    ) -> Result<(), SyncBackendError> {
        let mut state = self.inner.lock().unwrap();
        match &message {
            neutrin0_consensus_types::BftMessage::Proposal(proposal) => {
                if !state.bft_branch_ready {
                    return Err(SyncBackendError::NotAvailable("candidate branch".into()));
                }
                state.bft_round = proposal.round;
            }
            neutrin0_consensus_types::BftMessage::RoundChangeCertificate(certificate) => {
                state.bft_round = certificate.round;
            }
            _ => {}
        }
        state.bft_messages.push(message);
        drop(state);
        self.bft_notified.notify_one();
        Ok(())
    }
    async fn consensus_sync_target(
        &self,
    ) -> Result<Option<neutrin0_sync::backend::ConsensusSyncTarget>, SyncBackendError> {
        let state = self.inner.lock().unwrap();
        Ok(state.full_chunk_size.map(|size| {
            let base = state
                .bootstrap_endpoint
                .filter(|_| state.bootstrap_origin.is_none())
                .map_or(0, |endpoint| endpoint.boundary.next_chunk_id);
            let chunk_id = base + u64::try_from(state.chunk_proof_imports.len()).unwrap();
            neutrin0_sync::backend::ConsensusSyncTarget {
                chunk_id,
                start_height: chunk_id * size + 1,
                end_height: (chunk_id + 1) * size,
            }
        }))
    }
    async fn local_status(&self) -> Result<Status, SyncBackendError> {
        Ok(self.inner.lock().unwrap().status)
    }

    async fn local_progress(&self) -> Result<LocalProgress, SyncBackendError> {
        Ok({
            let (status, endpoint) = {
                let state = self.inner.lock().unwrap();
                if state.local_progress_error {
                    return Err(SyncBackendError::Storage(
                        "local progress unavailable".to_owned(),
                    ));
                }
                if let Some(progress) = state.local_progress_override {
                    return Ok(progress);
                }
                (
                    state.status,
                    state
                        .bootstrap_endpoint
                        .filter(|_| state.bootstrap_origin.is_none()),
                )
            };
            if let Some(endpoint) = endpoint {
                return Ok(LocalProgress {
                    chain_id: status.chain_id,
                    chain_spec_hash: status.chain_spec_hash,
                    finalized_chunk_id: status.finalized_chunk_id,
                    finalized_chunk_hash: status.finalized_chunk_hash,
                    checkpoint_hash: status.checkpoint_hash,
                    finalized_state_root: endpoint.boundary.state_root,
                    finalized_block_hash: endpoint.boundary.block_hash,
                    finalized_height: endpoint.boundary.height,
                    head_height: status.head_height,
                    head_block_hash: status.head_block_hash,
                    head_slot: status.head_slot,
                    proven_height: status.head_height,
                });
            }
            LocalProgress {
                chain_id: status.chain_id,
                chain_spec_hash: status.chain_spec_hash,
                finalized_chunk_id: None,
                finalized_chunk_hash: [0; 32],
                ..LocalProgress::default()
            }
        })
    }

    async fn bootstrap_origin(&self) -> Option<Checkpoint> {
        self.inner.lock().unwrap().bootstrap_origin
    }

    async fn bootstrap_fetch(&self, active: bool) {
        self.inner.lock().unwrap().bootstrap_fetching = active;
    }

    async fn bootstrap_state(
        &self,
    ) -> Result<Option<(StateRoot, Vec<StateItem>)>, SyncBackendError> {
        Ok(self.inner.lock().unwrap().bootstrap_pending.clone())
    }

    async fn restart_state_fragments(&self, items: &[StateItem]) -> Result<(), SyncBackendError> {
        let mut state = self.inner.lock().unwrap();
        state.state_restarts.push(items.to_vec());
        if let Some((_, pending)) = &mut state.bootstrap_pending {
            for item in pending {
                item.offset = 0;
            }
        }
        drop(state);
        Ok(())
    }

    // Driver tests validate RPC sequencing. The real backend's cryptographic,
    // consensus-context and state authentication are tested in the node crate.
    async fn begin_bootstrap(
        &self,
        anchor: Option<neutrin0_consensus_types::AnchorOpening>,
        data: BootstrapData,
    ) -> Result<StateProgress, SyncBackendError> {
        let endpoint = data.history.end_checkpoint();
        let items = vec![StateItem::node(endpoint.boundary.state_root)];
        {
            let mut state = self.inner.lock().unwrap();
            let origin = state.bootstrap_origin.expect("bootstrap test origin");
            // Only an anchor strictly between genesis and the endpoint is opened.
            let needs_opening = origin.boundary.next_chunk_id != 0 && origin != endpoint;
            if anchor.is_some() != needs_opening {
                return Err(SyncBackendError::Rejected("wrong test anchor".into()));
            }
            state.bootstrap_imports += 1;
            state.bootstrap_endpoint = Some(endpoint);
            state.bootstrap_pending = Some((endpoint.boundary.state_root, items.clone()));
        }
        Ok(StateProgress {
            root_complete: false,
            next_items: items,
        })
    }

    async fn history_proof(
        &self,
        anchor: CheckpointIndex,
        end: CheckpointIndex,
        _checkpoint: Hash,
    ) -> Result<HistoryProofResponse, SyncBackendError> {
        self.inner
            .lock()
            .unwrap()
            .rpc_calls
            .push(format!("history_proof({anchor},{end})"));
        Err(SyncBackendError::NotAvailable(
            "mock has no History proof".to_owned(),
        ))
    }

    async fn blocks_by_range(
        &self,
        start: Height,
        count: u64,
        _head: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError> {
        if self.inner.lock().unwrap().slow_ranges {
            self.range_gate.0.acquire().await.unwrap().forget();
        }
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("blocks_by_range({start},{count})"));
            BlocksByRangeResponse::default()
        })
    }

    async fn state_nodes(
        &self,
        _root: StateRoot,
        _items: &[neutrin0_consensus_types::bootstrap::StateItem],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        Ok(StateByRootResponse::default())
    }

    async fn chunk_proofs_by_id(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        Ok({
            self.inner
                .lock()
                .unwrap()
                .rpc_calls
                .push(format!("chunk_proofs_by_id({})", chunk_ids.len()));
            ChunkProofByIdResponse::default()
        })
    }

    async fn verify_history_conflict(&self, proof: HistoryProof) -> Result<bool, SyncBackendError> {
        let mut state = self.inner.lock().unwrap();
        state.rpc_calls.push("history_conflict".to_owned());
        state
            .conflict_endpoints
            .insert(proof.end_checkpoint().hash());
        Ok(state.conflict_endpoints.len() > 1)
    }

    async fn history_halted(&self) -> bool {
        self.inner.lock().unwrap().conflict_endpoints.len() > 1
    }

    async fn verify_and_import_history(
        &self,
        proof: HistoryProof,
        _anchor: Option<neutrin0_consensus_types::AnchorOpening>,
    ) -> Result<CheckpointsImported, SyncBackendError> {
        let checkpoint = proof.end_checkpoint();
        let mut state = self.inner.lock().unwrap();
        let target = state.advance_to_index;
        state.rpc_calls.push("history_import".to_owned());
        drop(state);
        Ok(CheckpointsImported {
            new_finalized_index: target,
            new_finalized_hash: checkpoint.hash(),
            new_finalized_state_root: checkpoint.boundary.state_root,
            new_finalized_height: checkpoint.boundary.height,
            new_finalized_block_hash: checkpoint.boundary.block_hash,
        })
    }

    async fn verify_and_import_candidates(
        &self,
        candidates: Vec<neutrin0_consensus_types::CandidateBlock>,
    ) -> Result<HeadersImported, SyncBackendError> {
        if self.inner.lock().unwrap().gossip_chain_behind {
            return Err(SyncBackendError::ChainBehind(
                "previous chunk unavailable".into(),
            ));
        }
        let last = candidates
            .last()
            .map(|candidate| candidate.block.clone())
            .ok_or_else(|| {
                SyncBackendError::Rejected("empty candidate batch in mock".to_owned())
            })?;
        {
            let mut state = self.inner.lock().unwrap();
            for candidate in &candidates {
                let height = candidate.block.header.height;
                state.imported_block_heights.insert(height);
                state.candidate_heights.push(height);
            }
        }
        Ok(HeadersImported {
            new_head_height: last.header.height,
            new_head_hash: last.hash(),
            new_head_slot: last.header.slot,
        })
    }

    async fn verify_and_import_receipts(
        &self,
        receipts: Vec<neutrin0_consensus_types::BlockReceipt>,
        _source: PeerId,
    ) -> Result<neutrin0_sync::ReceiptsImported, SyncBackendError> {
        let mut state = self.inner.lock().unwrap();
        if state.receipts_reject {
            return Err(SyncBackendError::Rejected(
                "receipt rejected by mock".to_owned(),
            ));
        }
        let mut imported = neutrin0_sync::ReceiptsImported::default();
        for receipt in receipts {
            if state.missing_receipts.contains(&receipt.block_hash) {
                state
                    .missing_receipts
                    .retain(|hash| *hash != receipt.block_hash);
                state.bft_branch_ready = state.missing_receipts.is_empty();
            }
            state.receipt_hashes.push(receipt.block_hash);
            if state.receipts_buffer {
                imported.buffered += 1;
            } else {
                imported.proven.push(1);
            }
        }
        Ok(imported)
    }

    async fn verify_and_import_proven_blocks(
        &self,
        blocks: Vec<neutrin0_consensus_types::ProvenBlock>,
    ) -> Result<HeadersImported, SyncBackendError> {
        if self.inner.lock().unwrap().gossip_chain_behind {
            return Err(SyncBackendError::ChainBehind(
                "previous chunk unavailable".into(),
            ));
        }
        let last = blocks
            .last()
            .map(|bundle| bundle.block.clone())
            .ok_or_else(|| SyncBackendError::Rejected("empty block batch in mock".to_owned()))?;
        let target = {
            let mut state = self.inner.lock().unwrap();
            for bundle in &blocks {
                let height = bundle.block.header.height;
                state.imported_block_heights.insert(height);
                state.proven_bundle_heights.push(height);
            }
            if state.full_chunk_size.is_some() {
                state.status.head_height = last.header.height;
            }
            state.proofs_imported_count += 1;
            state.proven_height = last.header.height;
            state.advance_to_height
        };
        self.proofs_notified.notify_one();
        Ok(HeadersImported {
            new_head_height: if target == 0 {
                last.header.height
            } else {
                target
            },
            new_head_hash: last.hash(),
            new_head_slot: last.header.slot,
        })
    }

    async fn import_state_nodes(
        &self,
        root: StateRoot,
        items: Vec<StateItem>,
        _entries: Vec<neutrin0_consensus_types::bootstrap::StateEntry>,
    ) -> Result<StateProgress, SyncBackendError> {
        {
            let mut state = self.inner.lock().unwrap();
            if !state.state_progress.is_empty() {
                state.state_fragments.extend(items);
                let progress = state.state_progress.remove(0);
                state.bootstrap_pending = Some((root, progress.next_items.clone()));
                return Ok(progress);
            }
            if let Some((expected, _)) = &state.bootstrap_pending {
                assert_eq!(root, *expected);
                state.state_fragments.extend(items);
                state.bootstrap_pending = None;
                state.bootstrap_origin = None;
                state.bootstrap_fetching = false;
                let endpoint = state.bootstrap_endpoint.expect("bootstrap endpoint");
                state.status.finalized_chunk_id = endpoint.boundary.next_chunk_id.checked_sub(1);
                state.status.head_height = endpoint.boundary.height;
                state.status.head_block_hash = endpoint.boundary.block_hash;
                state.status.checkpoint_hash = endpoint.hash();
            }
        }
        Ok(StateProgress {
            root_complete: true,
            next_items: vec![],
        })
    }

    async fn verify_and_import_chunk_proof(
        &self,
        proof: ChunkProof,
        _source: neutrin0_network::PeerId,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        let chunk_id = proof.chunk_id;
        let end_height = proof.public_inputs.end_height;
        self.inner
            .lock()
            .unwrap()
            .chunk_proof_imports
            .push(chunk_id);
        Ok(ChunkProofImported {
            chunk_id,
            end_height,
        })
    }

    async fn ingest_finality_vote(&self, _vote: FinalityVote) -> Result<(), SyncBackendError> {
        let admission_error = self.inner.lock().unwrap().admission_error.clone();
        if let Some(error) = admission_error {
            return Err(error);
        }
        self.inner.lock().unwrap().finality_vote_count += 1;
        Ok(())
    }

    async fn ingest_aggregate_finality_vote(
        &self,
        _subnet: u8,
        _vote: FinalityVote,
    ) -> Result<(), SyncBackendError> {
        let admission_error = self.inner.lock().unwrap().admission_error.clone();
        if let Some(error) = admission_error {
            return Err(error);
        }
        self.inner.lock().unwrap().aggregate_finality_vote_count += 1;
        Ok(())
    }

    async fn ingest_slashing_evidence(
        &self,
        _evidence: SlashingEvidence,
    ) -> Result<(), SyncBackendError> {
        let admission_error = self.inner.lock().unwrap().admission_error.clone();
        if let Some(error) = admission_error {
            return Err(error);
        }
        self.inner.lock().unwrap().slashing_evidence_count += 1;
        Ok(())
    }

    async fn ingest_evidence_proof(
        &self,
        report: neutrin0_consensus_types::evidence::EvidenceReport,
    ) -> neutrin0_sync::EvidenceProofAcceptance {
        self.inner.lock().unwrap().evidence_reports.push(report);
        neutrin0_sync::EvidenceProofAcceptance::Accepted
    }

    fn supports_signed_artifact_sync(&self) -> bool {
        self.inner.lock().unwrap().availability_enabled
    }
    async fn signed_artifact_source_known(&self, chunk: ChunkId) -> bool {
        self.inner.lock().unwrap().availability_enabled && chunk == 0
    }
    async fn signed_artifact_matches_source(
        &self,
        artifact: &neutrin0_consensus_types::signed_artifacts::SignedArtifact,
        chunk: ChunkId,
    ) -> bool {
        artifact.chunk_id(1) == Some(chunk)
    }
    async fn signed_artifact_by_id(
        &self,
        id: Hash,
    ) -> Result<neutrin0_network::rpc::SignedArtifactByIdResponse, SyncBackendError> {
        self.inner
            .lock()
            .unwrap()
            .availability_sources
            .iter()
            .find(|source| source.id() == id)
            .cloned()
            .map(|artifact| neutrin0_network::rpc::SignedArtifactByIdResponse { artifact })
            .ok_or_else(|| SyncBackendError::NotAvailable("mock source unavailable".into()))
    }
    async fn signed_artifact_inventory(
        &self,
        chunk: ChunkId,
        after: Option<Hash>,
    ) -> Result<neutrin0_network::rpc::SignedArtifactInventoryByChunkResponse, SyncBackendError>
    {
        let mut entries: Vec<_> = self
            .inner
            .lock()
            .unwrap()
            .availability_sources
            .iter()
            .map(neutrin0_consensus_types::signed_artifacts::SignedArtifact::reference)
            .filter(|item| after.is_none_or(|cursor| item.id > cursor))
            .collect();
        entries.sort_by_key(|item| item.id);
        entries.truncate(32);
        Ok(
            neutrin0_consensus_types::signed_artifacts::SignedArtifactInventory {
                chunk_id: chunk,
                entries,
                next: None,
            },
        )
    }
    async fn ingest_signed_artifact(
        &self,
        source: neutrin0_consensus_types::signed_artifacts::SignedArtifact,
    ) -> neutrin0_sync::EvidenceProofAcceptance {
        if self.inner.lock().unwrap().availability_deferred {
            return neutrin0_sync::EvidenceProofAcceptance::Deferred;
        }
        self.inner.lock().unwrap().availability_sources.push(source);
        self.availability_notified.notify_one();
        neutrin0_sync::EvidenceProofAcceptance::Accepted
    }
    async fn missing_vote_artifacts(
        &self,
        _vote: &FinalityVote,
    ) -> Vec<neutrin0_consensus_types::signed_artifacts::SignedArtifactRef> {
        self.inner.lock().unwrap().availability_missing.clone()
    }
}

fn random_peer() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn peer_connected_triggers_outbound_status_handshake() {
    let backend = MockBackend::default();
    backend.set_status(Status {
        chain_id: 1,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 0,
        head_height: 0,
    });
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 1,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let peer = random_peer();
    event_tx
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("a command")
        .expect("channel open");
    match cmd {
        NetworkCommand::SendRpcRequest {
            peer: p, request, ..
        } => {
            assert_eq!(p, peer);
            assert_eq!(request.protocol(), RpcProtocol::Status);
        }
        other => panic!("expected SendRpcRequest, got {other:?}"),
    }
    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn inbound_status_request_is_served_from_backend() {
    let backend = MockBackend::default();
    let local_status = Status {
        chain_id: 9,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [0xAA; 32],
        head_block_hash: [0xBB; 32],
        head_slot: 99,
        head_height: 88,
    };
    backend.set_status(local_status);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 9,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let peer = random_peer();
    let inbound_id = RpcInboundId {
        protocol: RpcProtocol::Status,
        raw: 1,
    };
    let peer_status = Status {
        chain_id: 9,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 1,
        head_height: 1,
    };
    event_tx
        .send(NetworkEvent::RpcRequestReceived {
            peer,
            inbound_id,
            request: RpcRequest::Status(peer_status),
        })
        .await
        .unwrap();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("a command")
        .expect("channel open");
    match cmd {
        NetworkCommand::SendRpcResponse {
            inbound_id: id,
            response,
        } => {
            assert_eq!(id, inbound_id);
            assert!(matches!(response, RpcResponse::Status(s) if s == local_status));
        }
        other => panic!("expected SendRpcResponse, got {other:?}"),
    }

    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn inbound_metadata_request_advertises_full_node_role() {
    let backend = MockBackend::default();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress {
            chain_id: 1,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let inbound_id = RpcInboundId {
        protocol: RpcProtocol::Metadata,
        raw: 2,
    };
    event_tx
        .send(NetworkEvent::RpcRequestReceived {
            peer: random_peer(),
            inbound_id,
            request: RpcRequest::Metadata(MetadataRequest),
        })
        .await
        .unwrap();

    let cmd = timeout(Duration::from_secs(1), cmd_rx.recv())
        .await
        .expect("a command")
        .expect("channel open");
    match cmd {
        NetworkCommand::SendRpcResponse {
            inbound_id: id,
            response,
        } => {
            assert_eq!(id, inbound_id);
            assert!(
                matches!(response, RpcResponse::Metadata(meta) if meta.role_flags == role_flags::FULL_NODE)
            );
        }
        other => panic!("expected SendRpcResponse, got {other:?}"),
    }

    drop(event_tx);
    handle.await.unwrap();
}

/// A producer publication wrapping `block` with placeholder receipt bytes.
fn proven(block: Block) -> neutrin0_consensus_types::ProvenBlock {
    neutrin0_consensus_types::ProvenBlock {
        block,
        proof_bytes: vec![7; 4],
        writes: Vec::new(),
    }
}

fn proven_all(blocks: &[Block]) -> Vec<neutrin0_consensus_types::ProvenBlock> {
    blocks.iter().cloned().map(proven).collect()
}

const fn candidate(block: Block) -> neutrin0_consensus_types::CandidateBlock {
    neutrin0_consensus_types::CandidateBlock {
        block,
        writes: Vec::new(),
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_receipts_are_relayed_only_once_they_prove_a_block() {
    let backend = Arc::new(MockBackend::default());
    backend.set_status(Status {
        chain_id: 1,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 0,
        head_height: 0,
    });
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::clone(&backend) as Arc<dyn SyncBackend>,
        LocalProgress {
            chain_id: 1,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let receipt = |byte: u8| neutrin0_consensus_types::BlockReceipt {
        block_hash: [byte; 32],
        proof_bytes: vec![byte; 8],
    };
    // Proven: relayed. Kept for the orphan window: not relayed. Invalid:
    // rejected against its source.
    for (byte, buffer, reject) in [(1_u8, false, false), (2, true, false), (3, false, true)] {
        backend.set_receipt_disposition(buffer, reject);
        event_tx
            .send(NetworkEvent::GossipMessage {
                propagation_source: random_peer(),
                topic: neutrin0_network::Topic::Receipts,
                data: borsh::to_vec(&receipt(byte)).unwrap(),
                message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(vec![byte]),
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Undecodable bytes are rejected before reaching the backend.
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrin0_network::Topic::Receipts,
            data: vec![0xFF; 3],
            message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(vec![9]),
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(backend.receipt_hashes(), vec![[1; 32], [2; 32]]);
    let mut verdicts = Vec::new();
    while let Ok(command) = cmd_rx.try_recv() {
        if let NetworkCommand::ReportGossipValidation { acceptance, .. } = command {
            verdicts.push(acceptance);
        }
    }
    assert_eq!(
        verdicts,
        vec![
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Accept,
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Ignore,
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Reject,
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Reject,
        ]
    );

    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_candidate_is_imported_as_one_unit_and_inconsistent_write_sets_are_rejected() {
    let backend = Arc::new(MockBackend::default());
    backend.set_status(Status {
        chain_id: 1,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [0; 32],
        head_block_hash: [0; 32],
        head_slot: 0,
        head_height: 0,
    });
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::clone(&backend) as Arc<dyn SyncBackend>,
        LocalProgress {
            chain_id: 1,
            chain_spec_hash: [0; 32],
            finalized_chunk_id: None,
            finalized_chunk_hash: [0; 32],
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let mut inconsistent = candidate(sample_block(7, 2));
    inconsistent.writes = vec![
        neutrin0_consensus_types::StateWrite {
            key: b"b".to_vec(),
            value: None,
        },
        neutrin0_consensus_types::StateWrite {
            key: b"a".to_vec(),
            value: None,
        },
    ];
    let good = candidate(sample_block(5, 1));
    for (bundle, id) in [(inconsistent, b"bad".to_vec()), (good, b"good".to_vec())] {
        event_tx
            .send(NetworkEvent::GossipMessage {
                propagation_source: random_peer(),
                topic: neutrin0_network::Topic::Blocks,
                data: borsh::to_vec(&bundle).unwrap(),
                message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(id),
            })
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(backend.candidate_heights(), vec![5]);
    assert_eq!(backend.proven_bundle_heights(), Vec::<Height>::new());
    let mut verdicts = Vec::new();
    while let Ok(command) = cmd_rx.try_recv() {
        if let NetworkCommand::ReportGossipValidation { acceptance, .. } = command {
            verdicts.push(acceptance);
        }
    }
    assert_eq!(
        verdicts,
        vec![
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Reject,
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Accept,
        ]
    );

    drop(event_tx);
    handle.await.unwrap();
}

fn sample_block(height: Height, slot: u64) -> Block {
    use neutrin0_consensus_types::{Body, Header};

    let header = Header {
        height,
        slot,
        parent_hash: [0; 32],
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: [1; 32],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 0,
        timestamp: 1_800_000_000,
        signature: [0; 96],
    };
    Block {
        header,
        body: Body::default(),
    }
}

fn sample_block_proof(height: Height) -> BlockProof {
    use neutrin0_consensus_types::BlockProofPublicInputs;
    use neutrin0_primitives::ZERO_HASH;

    let byte = u8::try_from(height).expect("sample height fits u8");
    BlockProof {
        height,
        block_hash: [byte; 32],
        public_inputs: BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 1,
            height,
            parent_block_hash: ZERO_HASH,
            block_hash: [byte; 32],
            state_root_before: ZERO_HASH,
            state_root_after: ZERO_HASH,
            transactions_root: ZERO_HASH,
            receipt_root: ZERO_HASH,
            da_root: ZERO_HASH,
            vm_code_hash: ZERO_HASH,
            block_program: [0; 8],
            gas_used: 0,
            gas_limit: 1_000_000,
            proposer_address: [0u8; 32],
            runtime_extra: ZERO_HASH,
            inputs_root: [0; 32],
        },
        prover_address: [0; 32],
        statement_key: [0; 32],
        proof_bytes: vec![0xAA],
    }
}

fn sample_chunk_proof(chunk_id: ChunkId, end_height: Height) -> ChunkProof {
    use neutrin0_consensus_types::ChunkProofPublicInputs;
    use neutrin0_primitives::ZERO_HASH;
    ChunkProof {
        finality_cert: neutrin0_consensus_types::FinalityCert {
            proof_manifests: Vec::new(),
            proposal: neutrin0_consensus_types::BftProposal {
                chunk: neutrin0_consensus_types::Chunk {
                    next_identity_sanctions_root: [0; 32],

                    chunk_id,
                    start_height: 0,
                    end_height,
                    start_state_root: ZERO_HASH,
                    end_state_root: ZERO_HASH,
                    start_block_hash: ZERO_HASH,
                    end_block_hash: ZERO_HASH,
                    block_hash_root: ZERO_HASH,
                    block_proof_root: ZERO_HASH,
                    vrf_proof_root: ZERO_HASH,
                    active_validator_set_root: ZERO_HASH,
                    next_validator_set_root: ZERO_HASH,
                    da_root: ZERO_HASH,
                },
                round: 0,
                proposer_index: 0,
                valid_quorum: None,
                round_change_certificate: None,
                proposal_slot: 0,
                receipts: Vec::new(),
                ratified_chunk_proofs: Vec::new(),
                signature: [0; 96],
            },
            prevote_attestations: Vec::new(),
            precommit_attestations: Vec::new(),
            chunk_id,
            round: 0,
            chunk_hash: [0xCC; 32],
            prevote: neutrin0_consensus_types::AggregatedVote {
                aggregation_bits: neutrin0_primitives::BitVec::default(),
                signature: [0; 96],
            },
            precommit: neutrin0_consensus_types::AggregatedVote {
                aggregation_bits: neutrin0_primitives::BitVec::default(),
                signature: [0; 96],
            },
            active_validator_set_root: ZERO_HASH,
        },
        chunk_id,
        chunk_hash: [0xCC; 32],
        prover_address: [0; 32],
        public_inputs: ChunkProofPublicInputs {
            next_identity_sanctions_root: [0; 32],

            chunk_id,
            start_height: 0,
            end_height,
            start_state_root: ZERO_HASH,
            end_state_root: ZERO_HASH,
            start_block_hash: ZERO_HASH,
            end_block_hash: ZERO_HASH,
            block_hash_root: ZERO_HASH,
            block_proof_root: ZERO_HASH,
            vrf_proof_root: ZERO_HASH,
            active_validator_set_root: ZERO_HASH,
            next_validator_set_root: ZERO_HASH,
            da_root: ZERO_HASH,
        },
        proof_bytes: vec![0xBB],
    }
}

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)] // Two chunks plus a rejected proof exercise the complete RPC sequence.
async fn complete_sync_requires_chunk_proof_before_fetching_the_next_chunk() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let observer = backend.clone();
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        commands,
        event_rx,
    );
    let run = tokio::spawn(driver.run());
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let mut order = Vec::new();
    let mut branch = Vec::new();
    let mut parent = [0; 32];
    for height in 1..=4 {
        let mut block = sample_block(height, height);
        block.header.parent_hash = parent;
        parent = block.hash();
        branch.push(block);
    }
    while observer.chunk_proof_imports().len() < 2 {
        let command = timeout(Duration::from_secs(10), received.recv())
            .await
            .unwrap()
            .unwrap();
        let NetworkCommand::SendRpcRequest {
            request,
            response_tx,
            ..
        } = command
        else {
            continue;
        };
        let response = match request {
            RpcRequest::Status(_) => RpcResponse::Status(Status {
                head_height: 4,
                head_block_hash: branch.last().unwrap().hash(),
                finalized_chunk_id: Some(1),
                finalized_chunk_hash: [0xCC; 32],
                ..Status::default()
            }),
            RpcRequest::BlocksByRange(request) => {
                order.push(format!("blocks {}", request.start_height));
                assert_eq!(request.count, 2);
                if request.start_height == 3 {
                    assert_eq!(observer.chunk_proof_imports(), vec![0]);
                }
                RpcResponse::BlocksByRange(BlocksByRangeResponse {
                    blocks: (request.start_height..request.start_height + request.count)
                        .map(|height| proven(branch[usize::try_from(height - 1).unwrap()].clone()))
                        .collect(),
                    candidates: Vec::new(),
                })
            }
            RpcRequest::ChunkProofById(request) => {
                let id = request.chunk_ids[0];
                order.push(format!("finality {id}"));
                let mut proof = sample_chunk_proof(id, (id + 1) * 2);
                proof.public_inputs.end_block_hash =
                    branch[usize::try_from((id + 1) * 2 - 1).unwrap()].hash();
                RpcResponse::ChunkProofById(ChunkProofByIdResponse {
                    proofs: vec![proof],
                })
            }
            other => panic!("unexpected request {other:?}"),
        };
        response_tx.send(Ok(response)).unwrap();
        if order.len() == 4 {
            timeout(Duration::from_secs(3), async {
                while observer.chunk_proof_imports().len() < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }
    assert_eq!(order, ["blocks 1", "finality 0", "blocks 3", "finality 1"]);
    drop(events);
    run.await.unwrap();
}

async fn next_full_sync_request(
    commands: &mut mpsc::Receiver<NetworkCommand>,
) -> (RpcRequest, HistoryReply) {
    loop {
        match timeout(Duration::from_secs(6), commands.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkCommand::SendRpcRequest {
                request,
                response_tx,
                ..
            } => return (request, response_tx),
            NetworkCommand::Subscribe(_) => {}
            other => panic!("unexpected full-sync command {other:?}"),
        }
    }
}

fn linked_full_sync_blocks() -> Vec<Block> {
    let first = sample_block(1, 1);
    let mut second = sample_block(2, 2);
    second.header.parent_hash = first.hash();
    vec![first, second]
}

async fn next_full_sync_payload_request(
    commands: &mut mpsc::Receiver<NetworkCommand>,
    status: Status,
) -> (RpcRequest, HistoryReply) {
    loop {
        let (request, response) = next_full_sync_request(commands).await;
        if matches!(request, RpcRequest::Status(_)) {
            response.send(Ok(RpcResponse::Status(status))).unwrap();
        } else {
            return (request, response);
        }
    }
}

async fn assert_no_full_sync_payload_request(
    commands: &mut mpsc::Receiver<NetworkCommand>,
    status: Status,
) {
    // A periodic Status may already be queued before the new payload request.
    // Reply explicitly: a wrongly released slot then emits another payload,
    // which fails this assertion across two paused-time retry intervals.
    let request = timeout(Duration::from_secs(11), async {
        loop {
            match commands.recv().await.expect("driver command channel") {
                NetworkCommand::SendRpcRequest {
                    request: RpcRequest::Status(_),
                    response_tx,
                    ..
                } => response_tx.send(Ok(RpcResponse::Status(status))).unwrap(),
                NetworkCommand::SendRpcRequest { request, .. } => return request,
                NetworkCommand::Subscribe(_) => {}
                other => panic!("unexpected full-sync command {other:?}"),
            }
        }
    })
    .await;
    assert!(
        request.is_err(),
        "obsolete response released active payload request: {request:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn full_sync_does_not_repeat_payload_requests_below_a_provider_pruning_floor() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let run = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            LocalProgress::default(),
            commands,
            event_rx,
        )
        .run(),
    );
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let status = Status {
        finalized_chunk_id: Some(3),
        finalized_chunk_hash: [3; 32],
        head_height: 8,
        head_block_hash: [8; 32],
        ..Status::default()
    };
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 1));
    response
        .send(Err(neutrin0_network::rpc::RpcError::Remote(
            neutrin0_network::rpc::RpcFailure::Pruned {
                retained_from_chunk: 2,
                retained_from_height: 5,
            },
        )))
        .unwrap();
    for _ in 0..3 {
        let (request, response) = next_full_sync_request(&mut received).await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response.send(Ok(RpcResponse::Status(status))).unwrap();
    }
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    backend.inner.lock().unwrap().chunk_proof_imports = vec![0, 1];
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, _response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 5));
    drop(events);
    run.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn stale_pruned_response_cannot_poison_a_reconnected_providers_availability() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let run = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend),
            LocalProgress::default(),
            commands,
            event_rx,
        )
        .run(),
    );
    let peer = random_peer();
    let status = Status {
        head_height: 8,
        head_block_hash: [8; 32],
        ..Status::default()
    };
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (_, response) = next_full_sync_request(&mut received).await;
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, old_response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(_)));
    events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, current_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 1));
    old_response
        .send(Err(neutrin0_network::rpc::RpcError::Remote(
            neutrin0_network::rpc::RpcFailure::Pruned {
                retained_from_chunk: 2,
                retained_from_height: 5,
            },
        )))
        .unwrap();
    assert_no_full_sync_payload_request(&mut received, status).await;
    current_response
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: proven_all(&linked_full_sync_blocks()),
            candidates: Vec::new(),
        })))
        .unwrap();
    // The chunk's proven blocks are complete; without an advertised finalized
    // chunk there is nothing further to request from this provider.
    assert_no_full_sync_payload_request(&mut received, status).await;
    drop(events);
    run.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn stale_block_response_cannot_release_a_reconnected_request_or_rewind_its_cursor() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(2);
    let observer = backend.clone();
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let run = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend),
            LocalProgress::default(),
            commands,
            event_rx,
        )
        .run(),
    );
    let peer = random_peer();
    let status = Status {
        head_height: 8,
        head_block_hash: [8; 32],
        finalized_chunk_id: Some(3),
        ..Status::default()
    };
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(
        matches!(&request, RpcRequest::Status(_)),
        "expected initial Status, got {request:?}"
    );
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, old_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(
        matches!(&request, RpcRequest::BlocksByRange(_)),
        "expected initial Blocks, got {request:?}"
    );
    events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (request, response) = next_full_sync_request(&mut received).await;
    assert!(
        matches!(&request, RpcRequest::Status(_)),
        "expected reconnect Status, got {request:?}"
    );
    response.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, current_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(
        matches!(&request, RpcRequest::BlocksByRange(range) if range.start_height == 1),
        "expected reconnect Blocks from 1, got {request:?}"
    );
    let blocks = linked_full_sync_blocks();
    current_response
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: proven_all(&blocks),
            candidates: Vec::new(),
        })))
        .unwrap();
    let (request, _finality_response) = next_full_sync_payload_request(&mut received, status).await;
    assert!(
        matches!(&request, RpcRequest::ChunkProofById(range) if range.chunk_ids == vec![0]),
        "expected current Finality for chunk 0, got {request:?}"
    );
    old_response
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: proven_all(&blocks[..1]),
            candidates: Vec::new(),
        })))
        .unwrap();
    assert_no_full_sync_payload_request(&mut received, status).await;
    assert_eq!(observer.inner.lock().unwrap().status.head_height, 2);
    drop(events);
    run.await.unwrap();
}

fn sample_finality_vote(chunk_id: ChunkId) -> FinalityVote {
    use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase};
    use neutrin0_primitives::BitVec;
    FinalityVote {
        proof_manifests: Vec::new(),
        attestations: Vec::new(),
        aggregation_bits: BitVec::default(),
        data: FinalityVoteData {
            chunk_id,
            round: 0,
            chunk_hash: [0xAB; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Prevote,
        },
        signature: [0; 96],
    }
}

fn sample_slashing_evidence() -> SlashingEvidence {
    use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase, IndexedVote};
    let make_vote = |chunk_hash: [u8; 32]| IndexedVote {
        data: FinalityVoteData {
            chunk_id: 7,
            round: 0,
            chunk_hash,
            selection: [0; 32],
            phase: FinalityVotePhase::Prevote,
        },
        signature: [0; 96],
    };
    SlashingEvidence::DoublePrevote {
        validator_index: 3,
        vote_a: make_vote([0x11; 32]),
        vote_b: make_vote([0x22; 32]),
    }
}

/// Complete chunk gossip must reach the backend verification path.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_chunk_proof_is_dispatched_to_verifying_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let proof = sample_chunk_proof(42, 128);
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrin0_network::Topic::ChunkProofs,
            data: borsh::to_vec(&proof).unwrap(),
            message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(b"cp-1".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.chunk_proof_imports(), vec![42]);

    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_finality_vote_is_routed_to_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let vote = sample_finality_vote(7);
    let encoded = borsh::to_vec(&neutrin0_consensus_types::BftVote::Value(vote.clone())).unwrap();
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrin0_network::Topic::FinalityVotesPrevote,
            data: encoded.clone(),
            message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(b"fv-1".to_vec()),
        })
        .await
        .unwrap();
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrin0_network::Topic::FinalityVotesPrecommit,
            data: encoded,
            message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(b"fv-2".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.finality_vote_count(), 2);

    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_aggregate_finality_vote_is_routed_to_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let vote = sample_finality_vote(9);
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrin0_network::Topic::AggregateFinalityVotes(3),
            data: borsh::to_vec(&neutrin0_consensus_types::BftVote::Value(vote.clone())).unwrap(),
            message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(b"agg".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.aggregate_finality_vote_count(), 1);

    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn gossipped_slashing_evidence_is_routed_to_backend() {
    let backend = MockBackend::default();
    backend.set_status(Status::default());
    let backend_handle = backend.clone();
    let (cmd_tx, _cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());

    let evidence = sample_slashing_evidence();
    event_tx
        .send(NetworkEvent::GossipMessage {
            propagation_source: random_peer(),
            topic: neutrin0_network::Topic::SlashingEvidence,
            data: borsh::to_vec(&evidence).unwrap(),
            message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(b"sl-1".to_vec()),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(backend_handle.slashing_evidence_count(), 1);

    drop(event_tx);
    handle.await.unwrap();
}

fn sample_evidence_report() -> neutrin0_consensus_types::evidence::EvidenceReport {
    use neutrin0_consensus_types::{
        evidence::{
            EvidenceArtifact, EvidenceContext, EvidenceMembership, EvidenceReport,
            EvidenceStatement, SanctionKind, commitment,
        },
        history::HistoryPath,
    };
    use neutrin0_primitives::Validator;
    let statement = EvidenceStatement {
        reporter: None,
        chain_id: 1,
        chain_spec_hash: [1; 32],
        block_guest_vk_digest: [2; 8],
        context: EvidenceContext {
            source_runtime_code_hash: [0; 32],
            source_block_guest_vk_digest: [2; 8],
            chunk_id: 0,
            chunk_hash: [3; 32],
            end_height: 1,
            validators_root: [4; 32],
            seed: [5; 32],
            start_boundary: [0; 32],
        },
        offender: Validator {
            pubkey: [6; 48],
            withdrawal_credentials: neutrin0_primitives::runtime_account([7; 20]),
            effective_stake: 100,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        },
        kind: SanctionKind::Slash,
        offence_id: [8; 32],
        facts_commitment: [9; 32],
    };
    EvidenceReport {
        history: HistoryPath::build(&[commitment(&statement.context)], 0).unwrap(),
        artifact: EvidenceArtifact {
            membership: EvidenceMembership::build(core::slice::from_ref(&statement), 0, [10; 8])
                .unwrap(),
            evidence_guest_vk_digest: [11; 8],
            statement,
            proof_bytes: vec![12],
        },
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn evidence_gossip_requires_and_forwards_the_reporters_history_path() {
    let report = sample_evidence_report();
    let backend = MockBackend::default();
    let backend_handle = backend.clone();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());
    for (id, data) in [
        (b"report".to_vec(), borsh::to_vec(&report).unwrap()),
        (
            b"missing-path".to_vec(),
            borsh::to_vec(&report.artifact).unwrap(),
        ),
    ] {
        event_tx
            .send(NetworkEvent::GossipMessage {
                propagation_source: random_peer(),
                topic: neutrin0_network::Topic::EvidenceProofs,
                data,
                message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(id),
            })
            .await
            .unwrap();
    }
    let mut verdicts = Vec::new();
    while verdicts.len() < 2 {
        if let NetworkCommand::ReportGossipValidation { acceptance, .. } =
            timeout(Duration::from_secs(1), cmd_rx.recv())
                .await
                .unwrap()
                .unwrap()
        {
            verdicts.push(acceptance);
        }
    }
    assert_eq!(
        verdicts,
        vec![
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Accept,
            neutrin0_network::libp2p::gossipsub::MessageAcceptance::Reject,
        ]
    );
    assert_eq!(
        backend_handle.inner.lock().unwrap().evidence_reports,
        vec![report]
    );
    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn unavailable_backend_data_returns_an_explicit_rpc_reply() {
    use neutrin0_network::rpc::{HistoryProofRequest, RpcFailure};
    let (commands, mut received) = mpsc::channel(16);
    let (events, event_rx) = mpsc::channel(16);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(MockBackend::default()),
        LocalProgress::default(),
        commands,
        event_rx,
    );
    let run = tokio::spawn(driver.run());
    let inbound_id = RpcInboundId {
        protocol: RpcProtocol::HistoryProof,
        raw: 17,
    };
    events
        .send(NetworkEvent::RpcRequestReceived {
            peer: random_peer(),
            inbound_id,
            request: RpcRequest::HistoryProof(HistoryProofRequest {
                anchor_chunks: 0,
                end_chunks: 1,
                checkpoint_hash: [1; 32],
                bootstrap: false,
            }),
        })
        .await
        .unwrap();
    let command = timeout(Duration::from_secs(1), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(command, NetworkCommand::SendRpcResponse { inbound_id: id, response: RpcResponse::Error { protocol: RpcProtocol::HistoryProof, error: RpcFailure::Unavailable(_) } } if id == inbound_id)
    );
    drop(events);
    run.await.unwrap();
}

const fn sample_chain() -> neutrin0_consensus_types::history_proof::ChainBinding {
    neutrin0_consensus_types::history_proof::ChainBinding {
        chain_spec_hash: [0; 32],
    }
}

/// Boundary at `count` chunks of a two-block-chunk fixture chain.
const fn sample_boundary(count: u64) -> neutrin0_consensus_types::history_proof::ConsensusBoundary {
    use neutrin0_consensus_types::history_proof::{
        ConsensusBoundary, ExecutionPrograms, ProgramSet,
    };
    ConsensusBoundary {
        identity_sanctions_root: [0; 32],
        participation: [0; 32],
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        next_chunk_id: count,
        height: 2 * count,
        block_hash: [1; 32],
        state_root: [2; 32],
        slot: 2 * count,
        validators_root: [3; 32],
        seed: [4; 32],
        history_root: [5; 32],
        programs: ProgramSet {
            runtime_code_hash: [2; 32],
            execution: ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
        },
        fork: None,
    }
}

/// Trusted anchor one chunk after genesis.
const fn sample_anchor() -> Checkpoint {
    Checkpoint {
        chain: sample_chain(),
        boundary: sample_boundary(1),
    }
}

/// Receipt of chunk 4, the History proof of the endpoint at five chunks.
fn sample_history_proof() -> HistoryProof {
    use neutrin0_consensus_types::history_proof::{ChunkReceiptStatement, ConsensusStatement};
    let start = sample_boundary(4);
    HistoryProof {
        statement: ChunkReceiptStatement {
            statement: ConsensusStatement {
                chain: sample_chain(),
                start,
                end: neutrin0_consensus_types::history_proof::ConsensusBoundary {
                    block_hash: [6; 32],
                    state_root: [7; 32],
                    history_root: [8; 32],
                    ..sample_boundary(5)
                },
                chunk: sample_chunk_proof(4, 10).public_inputs,
                finality_cert_hash: [0; 32],
            },
            chunk_prover_address: [0; 32],
        },
        receipt: neutrin0_primitives::BoundedBytes::new(vec![1]).unwrap(),
    }
}

/// Opaque opening of a fixture anchor; transport tests never verify it.
fn sample_opening(anchor: u64, end: u64) -> neutrin0_consensus_types::AnchorOpening {
    neutrin0_consensus_types::AnchorOpening {
        context: neutrin0_consensus_types::evidence::EvidenceContext {
            chunk_id: anchor,
            chunk_hash: [1; 32],
            end_height: 2 * anchor + 2,
            validators_root: [3; 32],
            seed: [4; 32],
            source_block_guest_vk_digest: [3; 8],
            source_runtime_code_hash: [2; 32],
            start_boundary: sample_boundary(anchor).commitment(),
        },
        path: neutrin0_consensus_types::history::HistoryPath {
            index: anchor,
            count: end,
            siblings: vec![[0; 32]; 64],
        },
    }
}

/// A light client asks for the latest proof alone, without an opening.
fn history_reply(proof: &HistoryProof) -> RpcResponse {
    RpcResponse::HistoryProof(Box::new(HistoryProofResponse {
        proof: proof.clone(),
        anchor: None,
        bootstrap: None,
    }))
}

type HistoryReply =
    tokio::sync::oneshot::Sender<Result<RpcResponse, neutrin0_network::rpc::RpcError>>;

struct PendingLightRange {
    backend: MockBackend,
    proof: HistoryProof,
    events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    runner: tokio::task::JoinHandle<()>,
    peer: PeerId,
    status: Status,
    response: Option<HistoryReply>,
}

impl PendingLightRange {
    async fn new() -> Self {
        let backend = MockBackend::default();
        backend.inner.lock().unwrap().full_chunk_size = Some(2);
        backend.set_advance(5, 10);
        let proof = sample_history_proof();
        let local = LocalProgress {
            chain_id: 1,
            finalized_chunk_id: Some(0),
            checkpoint_hash: sample_anchor().hash(),
            head_height: 2,
            ..LocalProgress::default()
        };
        let (cmd_tx, commands) = mpsc::channel(32);
        let (events, event_rx) = mpsc::channel(32);
        // Provider mechanics with one sampled peer; quorum sampling has its
        // own tests.
        let driver = SyncDriver::new(
            SyncDriverConfig {
                mode: neutrin0_network::SyncMode::LightClient,
                light_sampling: neutrin0_network::sync::SamplingPolicy {
                    peers: 1,
                    quorum: 1,
                },
                ..SyncDriverConfig::default()
            },
            Arc::new(backend.clone()),
            local,
            cmd_tx,
            event_rx,
        );
        let mut pending = Self {
            events,
            commands,
            runner: tokio::spawn(driver.run()),
            peer: random_peer(),
            status: Status {
                chain_id: 1,
                chain_spec_hash: [0; 32],
                finalized_chunk_id: Some(4),
                finalized_chunk_hash: [4; 32],
                checkpoint_hash: proof.end_checkpoint().hash(),
                head_block_hash: [6; 32],
                head_slot: 10,
                head_height: 10,
            },
            response: None,
            backend,
            proof,
        };
        pending
            .events
            .send(NetworkEvent::PeerConnected(pending.peer))
            .await
            .unwrap();
        pending.reply_status().await;
        pending.response = Some(pending.suffix_request().await);
        pending
    }

    async fn next_request(&mut self) -> (PeerId, RpcRequest, HistoryReply) {
        loop {
            match self.commands.recv().await.unwrap() {
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => return (peer, request, response_tx),
                NetworkCommand::ReportGossipValidation { acceptance, .. } => assert_eq!(
                    acceptance,
                    neutrin0_network::libp2p::gossipsub::MessageAcceptance::Accept
                ),
                other => panic!("unexpected command {other:?}"),
            }
        }
    }

    async fn reply_status(&mut self) {
        let (_, request, response) = self.next_request().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response.send(Ok(RpcResponse::Status(self.status))).unwrap();
    }

    async fn suffix_request(&mut self) -> HistoryReply {
        let (_, request, response) = self.next_request().await;
        // The client asks for the opening of its own endpoint, one chunk.
        assert!(matches!(request, RpcRequest::HistoryProof(ref request)
            if request.anchor_chunks == 1
                && request.end_chunks == 5
                && request.checkpoint_hash == self.status.checkpoint_hash));
        response
    }

    fn unavailable(&mut self) {
        self.response
            .take()
            .unwrap()
            .send(Err(neutrin0_network::rpc::RpcError::Remote(
                neutrin0_network::rpc::RpcFailure::Unavailable("pending".to_owned()),
            )))
            .unwrap();
    }

    async fn announce(&self) {
        let data = borsh::to_vec(&neutrin0_network::rpc::CheckpointAnnouncement {
            chunk_count: self.status.finalized_chunks(),
            checkpoint_hash: self.status.checkpoint_hash,
        })
        .unwrap();
        let message_id = neutrin0_network::libp2p::gossipsub::MessageId::from(
            neutrin0_primitives::blake3_256(&data).to_vec(),
        );
        self.events
            .send(NetworkEvent::GossipMessage {
                propagation_source: self.peer,
                topic: neutrin0_network::Topic::Checkpoints,
                data,
                message_id,
            })
            .await
            .unwrap();
    }

    async fn assert_quiescent(&mut self) {
        assert!(
            timeout(Duration::from_secs(1), self.next_request())
                .await
                .is_err()
        );
    }

    async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
#[allow(
    clippy::too_many_lines,
    reason = "The regression keeps an exact History reply live across repeated untrusted block hints."
)]
async fn ahead_gossip_cannot_reset_an_in_flight_authenticated_history_range() {
    let mut pending = PendingLightRange::new().await;
    pending.backend.inner.lock().unwrap().gossip_chain_behind = true;
    let other = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(other))
        .await
        .unwrap();
    pending.reply_status().await;
    for index in 0_u8..3 {
        let mut block = sample_block(100, 100);
        block.header.runtime_extra = [index; 32];
        pending
            .events
            .send(NetworkEvent::GossipMessage {
                propagation_source: pending.peer,
                topic: neutrin0_network::Topic::Blocks,
                data: borsh::to_vec(&candidate(block)).unwrap(),
                message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(vec![index]),
            })
            .await
            .unwrap();
    }
    let mut status_refreshes = 0;
    let mut ignored = 0;
    while ignored < 3 {
        match pending.commands.recv().await.unwrap() {
            NetworkCommand::SendRpcRequest {
                peer,
                request: RpcRequest::Status(_),
                response_tx,
            } => {
                assert_eq!(peer, pending.peer);
                status_refreshes += 1;
                response_tx
                    .send(Ok(RpcResponse::Status(pending.status)))
                    .unwrap();
            }
            NetworkCommand::ReportGossipValidation { acceptance, .. } => {
                assert_eq!(
                    acceptance,
                    neutrin0_network::libp2p::gossipsub::MessageAcceptance::Ignore
                );
                ignored += 1;
            }
            other => panic!("ahead hint disturbed active range: {other:?}"),
        }
    }
    assert_eq!(status_refreshes, 1);
    // The exact request issued before the unauthenticated hints is still live.
    pending
        .response
        .take()
        .unwrap()
        .send(Ok(history_reply(&pending.proof)))
        .unwrap();
    assert!(matches!(
        pending.commands.recv().await.unwrap(),
        NetworkCommand::Subscribe(neutrin0_network::Topic::Checkpoints)
    ));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn light_mode_requests_an_exact_suffix_even_with_a_full_backend() {
    let mut pending = PendingLightRange::new().await;
    pending.unavailable();
    pending.assert_quiescent().await;
    // The endpoint and peer status did not move, but a new suffix is now available.
    pending.announce().await;
    pending.reply_status().await;
    let _response = pending.suffix_request().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn range_notice_arriving_before_unavailable_response_is_not_lost() {
    let mut pending = PendingLightRange::new().await;
    pending.announce().await;
    pending.reply_status().await;
    // Status sees the old request still in flight, so it cannot fetch yet.
    pending.assert_quiescent().await;
    pending.unavailable();
    // The stored availability event refreshes status once after the old failure.
    pending.reply_status().await;
    let _response = pending.suffix_request().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn light_relay_miss_tries_a_connected_full_provider_for_the_same_range() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.unavailable();
    let (peer, request, response) = pending.next_request().await;
    assert_eq!(peer, provider);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.anchor_chunks == 1
            && request.checkpoint_hash == pending.proof.end_checkpoint().hash()));
    response.send(Ok(history_reply(&pending.proof))).unwrap();
    let command = pending.commands.recv().await.unwrap();
    assert!(matches!(
        command,
        NetworkCommand::Subscribe(neutrin0_network::Topic::Checkpoints)
    ));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pruned_history_provider_never_changes_the_clients_trusted_anchor() {
    let mut pending = PendingLightRange::new().await;
    let archive = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(archive))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending
        .response
        .take()
        .unwrap()
        .send(Err(neutrin0_network::rpc::RpcError::Remote(
            neutrin0_network::rpc::RpcFailure::Pruned {
                retained_from_chunk: 4,
                retained_from_height: 9,
            },
        )))
        .unwrap();
    let (provider, request, response) = pending.next_request().await;
    assert_eq!(provider, archive);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.anchor_chunks == 1
            && request.checkpoint_hash == pending.proof.end_checkpoint().hash()));
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    response.send(Ok(history_reply(&pending.proof))).unwrap();
    assert!(matches!(
        pending.commands.recv().await.unwrap(),
        NetworkCommand::Subscribe(neutrin0_network::Topic::Checkpoints)
    ));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn exhausted_history_providers_stay_quiet_without_another_availability_event() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.unavailable();
    let (peer, request, response) = pending.next_request().await;
    assert_eq!(peer, provider);
    assert!(matches!(request, RpcRequest::HistoryProof(_)));
    pending.response = Some(response);
    pending.unavailable();
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), Vec::<String>::new());
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reconnect_and_unchanged_status_do_not_rearm_an_exhausted_history_provider() {
    let mut pending = PendingLightRange::new().await;
    pending.unavailable();
    pending.assert_quiescent().await;
    for _ in 0..2 {
        pending
            .events
            .send(NetworkEvent::PeerDisconnected(pending.peer))
            .await
            .unwrap();
        pending
            .events
            .send(NetworkEvent::PeerConnected(pending.peer))
            .await
            .unwrap();
        pending.reply_status().await;
        pending.assert_quiescent().await;
    }
    pending.announce().await;
    pending.reply_status().await;
    let _response = pending.suffix_request().await;
    pending.stop().await;
}

async fn assert_disconnected_history_outcome_is_ignored(stale_success: bool) {
    let mut pending = PendingLightRange::new().await;
    let replacement = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(replacement))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    let (peer, request, current_response) = pending.next_request().await;
    assert_eq!(peer, replacement);
    assert!(matches!(request, RpcRequest::HistoryProof(_)));
    if stale_success {
        pending
            .response
            .take()
            .unwrap()
            .send(Ok(history_reply(&pending.proof)))
            .unwrap();
    } else {
        pending.unavailable();
    }
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    // A new provider's status cannot release the replacement's active slot.
    pending
        .events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    current_response
        .send(Ok(history_reply(&pending.proof)))
        .unwrap();
    assert!(matches!(
        pending.commands.recv().await.unwrap(),
        NetworkCommand::Subscribe(neutrin0_network::Topic::Checkpoints)
    ));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnected_history_failure_cannot_release_a_replacement_request() {
    assert_disconnected_history_outcome_is_ignored(false).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnected_history_success_cannot_import_or_release_a_replacement_request() {
    assert_disconnected_history_outcome_is_ignored(true).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn higher_status_during_history_request_is_fetched_after_current_success() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    let (_, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    let later = Status {
        finalized_chunk_id: Some(6),
        checkpoint_hash: [7; 32],
        head_height: 14,
        ..pending.status
    };
    response.send(Ok(RpcResponse::Status(later))).unwrap();
    pending.assert_quiescent().await;
    pending
        .response
        .take()
        .unwrap()
        .send(Ok(history_reply(&pending.proof)))
        .unwrap();
    // The sampled higher endpoint is fetched next, without following first,
    // with the opening of the five-chunk endpoint just imported.
    let (peer, request, _response) = pending.next_request().await;
    assert_eq!(peer, provider);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.anchor_chunks == 5 && request.checkpoint_hash == later.checkpoint_hash));
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn late_status_from_a_disconnected_provider_cannot_change_the_history_target() {
    let mut pending = PendingLightRange::new().await;
    let provider = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(provider))
        .await
        .unwrap();
    let (_, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(provider))
        .await
        .unwrap();
    pending.assert_quiescent().await;
    response
        .send(Ok(RpcResponse::Status(Status {
            finalized_chunk_id: Some(6),
            checkpoint_hash: [7; 32],
            ..pending.status
        })))
        .unwrap();
    pending.assert_quiescent().await;
    pending.unavailable();
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnect_replays_newer_deferred_status_even_after_old_range_provider_exhaustion() {
    let mut pending = PendingLightRange::new().await;
    let replacement = random_peer();
    pending
        .events
        .send(NetworkEvent::PeerConnected(replacement))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.unavailable();
    let (peer, _, response) = pending.next_request().await;
    assert_eq!(peer, replacement);
    pending.response = Some(response);
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending
        .events
        .send(NetworkEvent::PeerConnected(pending.peer))
        .await
        .unwrap();
    let (_, request, status_response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    let newer = Status {
        finalized_chunk_id: Some(6),
        checkpoint_hash: [7; 32],
        ..pending.status
    };
    status_response
        .send(Ok(RpcResponse::Status(newer)))
        .unwrap();
    pending.assert_quiescent().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(replacement))
        .await
        .unwrap();
    let (peer, request, _current_response) = pending.next_request().await;
    assert_eq!(peer, pending.peer);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.anchor_chunks == 1 && request.checkpoint_hash == newer.checkpoint_hash));
    pending.unavailable();
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn old_response_from_same_peer_and_range_cannot_replace_a_new_request() {
    let mut pending = PendingLightRange::new().await;
    let old_response = pending.response.take().unwrap();
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending
        .events
        .send(NetworkEvent::PeerConnected(pending.peer))
        .await
        .unwrap();
    pending.reply_status().await;
    pending.assert_quiescent().await;
    pending.announce().await;
    pending.reply_status().await;
    pending.response = Some(pending.suffix_request().await);
    old_response
        .send(Ok(history_reply(&pending.proof)))
        .unwrap();
    pending.assert_quiescent().await;
    assert_eq!(pending.backend.rpc_calls(), [] as [String; 0]);
    pending.unavailable();
    pending.assert_quiescent().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnecting_highest_deferred_peer_preserves_other_progress_notifications() {
    let mut pending = PendingLightRange::new().await;
    let highest = random_peer();
    let available = random_peer();
    for (peer, covered, endpoint) in [(highest, 10_u64, [10; 32]), (available, 7, [7; 32])] {
        pending
            .events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (_, request, response) = pending.next_request().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response
            .send(Ok(RpcResponse::Status(Status {
                finalized_chunk_id: covered.checked_sub(1),
                checkpoint_hash: endpoint,
                ..pending.status
            })))
            .unwrap();
        pending.assert_quiescent().await;
    }
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(highest))
        .await
        .unwrap();
    pending.assert_quiescent().await;
    pending
        .response
        .take()
        .unwrap()
        .send(Ok(history_reply(&pending.proof)))
        .unwrap();
    // The next request opens the five-chunk endpoint just imported.
    let (peer, request, _response) = pending.next_request().await;
    assert_eq!(peer, available);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.anchor_chunks == 5 && request.checkpoint_hash == [7; 32]));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn exhausted_deferred_hint_cannot_block_another_available_range() {
    let mut pending = PendingLightRange::new().await;
    for peer in [random_peer(), random_peer()] {
        pending
            .events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        pending.reply_status().await;
        pending.assert_quiescent().await;
    }
    pending.unavailable();
    let (second, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::HistoryProof(_)));
    pending.response = Some(response);
    pending.unavailable();
    let (_, request, response) = pending.next_request().await;
    assert!(matches!(request, RpcRequest::HistoryProof(_)));
    pending.response = Some(response);
    for (peer, covered, endpoint) in [
        (pending.peer, 5_u64, pending.status.checkpoint_hash),
        (second, 3, [3; 32]),
    ] {
        pending
            .events
            .send(NetworkEvent::PeerDisconnected(peer))
            .await
            .unwrap();
        pending
            .events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (_, request, response) = pending.next_request().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        response
            .send(Ok(RpcResponse::Status(Status {
                finalized_chunk_id: covered.checked_sub(1),
                checkpoint_hash: endpoint,
                ..pending.status
            })))
            .unwrap();
        pending.assert_quiescent().await;
    }
    pending.unavailable();
    let (peer, request, _response) = pending.next_request().await;
    assert_eq!(peer, second);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.anchor_chunks == 1 && request.checkpoint_hash == [3; 32]));
    pending.stop().await;
}

/// A light driver with the default five-peer, three-agreeing sampling.
fn sampling_light_driver(
    backend: &MockBackend,
) -> (
    mpsc::Sender<NetworkEvent>,
    mpsc::Receiver<NetworkCommand>,
    tokio::task::JoinHandle<()>,
) {
    let local = LocalProgress {
        chain_id: 1,
        finalized_chunk_id: Some(0),
        checkpoint_hash: sample_anchor().hash(),
        head_height: 2,
        ..LocalProgress::default()
    };
    let (cmd_tx, commands) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(64);
    let driver = SyncDriver::new(
        SyncDriverConfig {
            mode: neutrin0_network::SyncMode::LightClient,
            ..SyncDriverConfig::default()
        },
        Arc::new(backend.clone()),
        local,
        cmd_tx,
        event_rx,
    );
    (events, commands, tokio::spawn(driver.run()))
}

fn advertising(proof: &HistoryProof) -> Status {
    Status {
        chain_id: 1,
        chain_spec_hash: [0; 32],
        finalized_chunk_id: proof.end().next_chunk_id.checked_sub(1),
        finalized_chunk_hash: [4; 32],
        checkpoint_hash: proof.end_checkpoint().hash(),
        head_block_hash: [6; 32],
        head_slot: 10,
        head_height: 10,
    }
}

/// Connect `peer`, answer its status handshake and return the next request.
async fn sample(
    events: &mpsc::Sender<NetworkEvent>,
    commands: &mut mpsc::Receiver<NetworkCommand>,
    peer: PeerId,
    status: Status,
) {
    events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    loop {
        if let NetworkCommand::SendRpcRequest {
            request: RpcRequest::Status(_),
            response_tx,
            ..
        } = commands.recv().await.unwrap()
        {
            response_tx.send(Ok(RpcResponse::Status(status))).unwrap();
            return;
        }
    }
}

async fn next_history_request(
    commands: &mut mpsc::Receiver<NetworkCommand>,
) -> Option<(
    PeerId,
    neutrin0_network::rpc::HistoryProofRequest,
    HistoryReply,
)> {
    loop {
        match timeout(Duration::from_secs(1), commands.recv()).await {
            Ok(Some(NetworkCommand::SendRpcRequest {
                peer,
                request: RpcRequest::HistoryProof(request),
                response_tx,
            })) => return Some((peer, request, response_tx)),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return None,
        }
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn light_client_fetches_only_an_endpoint_a_quorum_of_peers_advertise() {
    let backend = MockBackend::default();
    backend.set_advance(5, 10);
    let proof = sample_history_proof();
    let (events, mut commands, runner) = sampling_light_driver(&backend);
    let peers = [random_peer(), random_peer(), random_peer()];
    for peer in &peers[..2] {
        sample(&events, &mut commands, *peer, advertising(&proof)).await;
    }
    // Two of the required three agree: nothing is fetched.
    assert!(next_history_request(&mut commands).await.is_none());
    sample(&events, &mut commands, peers[2], advertising(&proof)).await;
    let (peer, request, response) = next_history_request(&mut commands).await.unwrap();
    assert_eq!(peer, peers[2]);
    // The opening asked for is of the client's own endpoint.
    assert_eq!(request.anchor_chunks, 1);
    assert_eq!(request.end_chunks, 5);
    assert_eq!(request.checkpoint_hash, proof.end_checkpoint().hash());
    response.send(Ok(history_reply(&proof))).unwrap();
    tokio::task::yield_now().await;
    assert!(next_history_request(&mut commands).await.is_none());
    assert_eq!(backend.rpc_calls(), vec!["history_import"]);
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn verified_conflicting_proofs_halt_the_light_client() {
    let backend = MockBackend::default();
    backend.set_advance(5, 10);
    let proof = sample_history_proof();
    let mut fork = proof.clone();
    fork.statement.statement.end.block_hash = [99; 32];
    let (events, mut commands, runner) = sampling_light_driver(&backend);
    let (honest, forked) = (random_peer(), random_peer());
    sample(&events, &mut commands, honest, advertising(&proof)).await;
    sample(&events, &mut commands, forked, advertising(&fork)).await;
    // Each side is fetched from the peer advertising it, never accepted.
    let mut sides = Vec::new();
    for _ in 0..2 {
        let (peer, request, response) = next_history_request(&mut commands).await.unwrap();
        assert_eq!(request.anchor_chunks, 0);
        assert_eq!(request.end_chunks, 5);
        let side = if peer == honest { &proof } else { &fork };
        assert_eq!(request.checkpoint_hash, side.end_checkpoint().hash());
        sides.push(peer);
        response.send(Ok(history_reply(side))).unwrap();
    }
    sides.sort();
    let mut expected = vec![honest, forked];
    expected.sort();
    assert_eq!(sides, expected);
    tokio::task::yield_now().await;
    assert_eq!(
        backend.rpc_calls(),
        vec!["history_conflict", "history_conflict"]
    );
    // Halted: even a quorum for a later endpoint is not fetched.
    for _ in 0..3 {
        sample(&events, &mut commands, random_peer(), advertising(&proof)).await;
    }
    assert!(next_history_request(&mut commands).await.is_none());
    assert!(!backend.rpc_calls().contains(&"history_import".to_owned()));
    drop(events);
    runner.await.unwrap();
}

// These fixtures are transport-only: opaque receipts are never accepted by a
// production verifier. Node tests exercise authenticated checkpoint installation.
struct PendingBootstrap {
    backend: MockBackend,
    proof: HistoryProof,
    origin: Checkpoint,
    events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    runner: tokio::task::JoinHandle<()>,
    peer: PeerId,
    status: Status,
    sync_status: neutrin0_sync::SyncStatus,
}

impl PendingBootstrap {
    async fn new(resume: bool) -> Self {
        Self::with_origin(resume, false).await
    }

    async fn with_origin(resume: bool, genesis: bool) -> Self {
        let mut pending = Self::unconnected(resume, genesis);
        pending.connect(pending.peer).await;
        pending
    }

    /// Running driver whose provider has not connected yet.
    fn unconnected(resume: bool, genesis: bool) -> Self {
        let backend = MockBackend::default();
        let proof = sample_history_proof();
        let origin = if genesis {
            Checkpoint {
                chain: sample_chain(),
                boundary: sample_boundary(0),
            }
        } else {
            sample_anchor()
        };
        {
            let mut state = backend.inner.lock().unwrap();
            state.status.chain_id = 1;
            state.bootstrap_origin = Some(origin);
            if resume {
                let mut item = StateItem::value([9; 32]);
                item.offset = 65_536;
                state.bootstrap_endpoint = Some(proof.end_checkpoint());
                state.bootstrap_pending = Some((proof.end().state_root, vec![item]));
            }
        }
        let local = LocalProgress {
            chain_id: 1,
            ..LocalProgress::default()
        };
        let (cmd_tx, commands) = mpsc::channel(32);
        let (events, event_rx) = mpsc::channel(32);
        let driver = SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            local,
            cmd_tx,
            event_rx,
        );
        let sync_status = driver.status();
        Self {
            sync_status,
            backend,
            peer: random_peer(),
            status: Status {
                chain_id: 1,
                finalized_chunk_id: Some(4),
                checkpoint_hash: proof.end_checkpoint().hash(),
                head_block_hash: proof.end().block_hash,
                head_height: 10,
                head_slot: 10,
                ..Status::default()
            },
            proof,
            origin,
            events,
            commands,
            runner: tokio::spawn(driver.run()),
        }
    }

    async fn next(&mut self) -> (PeerId, RpcRequest, HistoryReply) {
        loop {
            match timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => return (peer, request, response_tx),
                NetworkCommand::Subscribe(_) => {}
                command => panic!("unexpected bootstrap command {command:?}"),
            }
        }
    }

    async fn connect(&mut self, peer: PeerId) {
        self.events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (owner, request, response) = self.next().await;
        assert_eq!(owner, peer);
        assert!(matches!(request, RpcRequest::Status(_)));
        response.send(Ok(RpcResponse::Status(self.status))).unwrap();
    }

    fn manifest(&self) -> RpcResponse {
        let data = BootstrapData::new(
            self.proof.clone(),
            sample_block(10, 10).header,
            vec![],
            neutrin0_consensus_types::history::HistoryFrontier::empty(),
            vec![],
        )
        .unwrap();
        let end = self.proof.end_checkpoint();
        let anchor = self.origin.boundary.next_chunk_id;
        RpcResponse::HistoryProof(Box::new(HistoryProofResponse {
            proof: self.proof.clone(),
            anchor: (anchor != 0 && self.origin != end)
                .then(|| sample_opening(anchor, end.boundary.next_chunk_id)),
            bootstrap: Some(data),
        }))
    }

    async fn history(&mut self) -> HistoryReply {
        let (_, request, response) = self.next().await;
        assert!(matches!(request, RpcRequest::HistoryProof(ref request)
            if request.bootstrap
                && request.anchor_chunks == self.origin.boundary.next_chunk_id
                && request.end_chunks == self.status.finalized_chunks()
                && request.checkpoint_hash == self.status.checkpoint_hash));
        response
    }

    async fn state(&mut self) -> (PeerId, Vec<StateItem>, HistoryReply) {
        let (peer, request, response) = self.next().await;
        let RpcRequest::StateByRoot(request) = request else {
            panic!("expected fragments, got {request:?}")
        };
        assert_eq!(request.state_root, self.proof.end().state_root);
        (peer, request.items.to_vec(), response)
    }

    async fn quiet(&mut self) {
        assert!(
            timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .is_err()
        );
    }

    async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap();
    }
}

fn bootstrap_unavailable(reply: HistoryReply) {
    reply
        .send(Err(neutrin0_network::rpc::RpcError::Remote(
            neutrin0_network::rpc::RpcFailure::Unavailable("snapshot unavailable".into()),
        )))
        .unwrap();
}

fn latest_anchor_bootstrap(resume: bool) -> (PendingBootstrap, PeerId) {
    let backend = MockBackend::default();
    let proof = sample_history_proof();
    let anchor = proof.end_checkpoint();
    {
        let mut state = backend.inner.lock().unwrap();
        state.status.chain_id = 1;
        state.bootstrap_origin = Some(anchor);
        if resume {
            state.bootstrap_endpoint = Some(anchor);
            state.bootstrap_pending = Some((
                anchor.boundary.state_root,
                vec![StateItem::node(anchor.boundary.state_root)],
            ));
        }
    }
    let (cmd_tx, commands) = mpsc::channel(32);
    let (events, event_rx) = mpsc::channel(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend.clone()),
        LocalProgress {
            chain_id: 1,
            ..LocalProgress::default()
        },
        cmd_tx,
        event_rx,
    );
    let sync_status = driver.status();
    // Equal-count ranking chooses the later key. Give that key to the peer whose
    // advertised checkpoint disagrees with the independently trusted endpoint.
    let mut peers = [random_peer(), random_peer()];
    peers.sort_unstable();
    (
        PendingBootstrap {
            sync_status,
            backend,
            proof,
            origin: anchor,
            events,
            commands,
            runner: tokio::spawn(driver.run()),
            peer: peers[1],
            status: Status {
                chain_id: 1,
                finalized_chunk_id: anchor.boundary.next_chunk_id.checked_sub(1),
                checkpoint_hash: anchor.hash(),
                ..Status::default()
            },
        },
        peers[0],
    )
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_ranking_skips_a_same_count_wrong_checkpoint() {
    let (mut pending, matching) = latest_anchor_bootstrap(false);
    pending.status.checkpoint_hash = [99; 32];
    pending.connect(pending.peer).await;
    pending.quiet().await;
    let anchor = pending.proof.end_checkpoint().hash();
    pending.status.checkpoint_hash = anchor;
    pending.connect(matching).await;
    let (owner, request, _reply) = pending.next().await;
    assert_eq!(owner, matching);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.bootstrap
            && request.anchor_chunks == 5
            && request.end_chunks == 5
            && request.checkpoint_hash == anchor));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_replacement_manifest_filters_endpoints_without_filtering_state_providers() {
    let (mut pending, matching) = latest_anchor_bootstrap(true);
    pending.status.checkpoint_hash = [99; 32];
    pending.connect(pending.peer).await;
    // An existing authenticated root can be served despite an unrelated advertised
    // checkpoint. The eligibility restriction applies only to new manifests.
    let (owner, items, first) = pending.state().await;
    assert_eq!(owner, pending.peer);
    let anchor = pending.proof.end_checkpoint().hash();
    pending.status.checkpoint_hash = anchor;
    pending.connect(matching).await;
    bootstrap_unavailable(first);
    let (owner, next_items, second) = pending.state().await;
    assert_eq!(owner, matching);
    assert_eq!(next_items, items);
    bootstrap_unavailable(second);
    // Both state providers failed, so request an eligible replacement manifest.
    let (owner, request, _reply) = pending.next().await;
    assert_eq!(owner, matching);
    assert!(matches!(request, RpcRequest::HistoryProof(ref request)
        if request.bootstrap
            && request.anchor_chunks == 5
            && request.end_chunks == 5
            && request.checkpoint_hash == anchor));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_requests_recursive_context_then_fragments_before_raw_blocks() {
    let mut pending = PendingBootstrap::new(false).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (_, items, reply) = pending.state().await;
    assert_eq!(items, vec![StateItem::node(pending.proof.end().state_root)]);
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);
    reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse {
            entries: StateEntries::default(),
        })))
        .unwrap();
    let (_, request, _reply) = pending.next().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    {
        let state = pending.backend.inner.lock().unwrap();
        assert_eq!(state.bootstrap_imports, 1);
        assert_eq!(state.state_fragments, items);
        assert_eq!(state.status.head_height, 10);
        assert!(!state.bootstrap_fetching);
        drop(state);
    }
    let mut metrics = String::new();
    pending.sync_status.render_metrics(&mut metrics);
    assert!(
        metrics
            .contains("neutrin0_sync_bootstrap_results_total{kind=\"history\",outcome=\"ok\"} 1")
    );
    assert!(
        metrics.contains("neutrin0_sync_bootstrap_results_total{kind=\"state\",outcome=\"ok\"} 1")
    );
    assert!(metrics.contains("neutrin0_sync_bootstrap_installs_total 1"));
    assert!(metrics.contains("neutrin0_sync_bootstrap_pending_items 0"));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_rejects_wrong_endpoint_before_backend_installation() {
    let mut pending = PendingBootstrap::new(false).await;
    let reply = pending.history().await;
    let RpcResponse::HistoryProof(mut response) = pending.manifest() else {
        unreachable!()
    };
    response.proof.statement.statement.end.block_hash = [99; 32];
    reply.send(Ok(RpcResponse::HistoryProof(response))).unwrap();
    pending.quiet().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    assert_eq!(pending.backend.inner.lock().unwrap().status.head_height, 0);
    assert!(pending.sync_status.is_syncing());
    assert!(!pending.sync_status.awaiting_first_peer());
    let mut metrics = String::new();
    pending.sync_status.render_metrics(&mut metrics);
    assert!(metrics.contains(
        "neutrin0_sync_bootstrap_results_total{kind=\"history\",outcome=\"rejected\"} 1"
    ));
    assert!(metrics.contains("neutrin0_sync_bootstrap_installs_total 0"));
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_restart_refetches_a_partly_received_object_from_byte_zero() {
    // Whoever staged the fragments before the restart is unknown, so the
    // object starts over rather than mix bytes from two providers.
    let mut pending = PendingBootstrap::new(true).await;
    let (_, items, _reply) = pending.state().await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].offset, 0);
    let (restarts, imports) = {
        let state = pending.backend.inner.lock().unwrap();
        (state.state_restarts.clone(), state.bootstrap_imports)
    };
    assert_eq!(restarts.len(), 1);
    assert_eq!(restarts[0][0].offset, 65_536);
    assert_eq!(imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_finishes_a_partial_object_from_its_provider_and_restarts_it_elsewhere() {
    let mut pending = PendingBootstrap::new(false).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (first, items, reply) = pending.state().await;
    let mut partial = items[0];
    partial.offset = 65_536;
    pending.backend.inner.lock().unwrap().state_progress = vec![
        StateProgress {
            root_complete: false,
            next_items: vec![partial],
        },
        StateProgress {
            root_complete: false,
            next_items: vec![partial],
        },
    ];
    let second = random_peer();
    pending.connect(second).await;
    reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse::default())))
        .unwrap();
    // The provider that began the object finishes it, from its offset.
    let (owner, continued, reply) = pending.state().await;
    assert_eq!(owner, first);
    assert_eq!(continued, vec![partial]);
    assert_eq!(
        pending.backend.inner.lock().unwrap().state_restarts,
        Vec::<Vec<StateItem>>::new()
    );
    // Once it fails, the next provider fetches the object from byte zero.
    bootstrap_unavailable(reply);
    let (replacement, restarted, _reply) = pending.state().await;
    assert_eq!(replacement, second);
    assert_eq!(restarted[0].offset, 0);
    assert_eq!(
        pending.backend.inner.lock().unwrap().state_restarts,
        vec![vec![partial]]
    );
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_disconnected_response_cannot_release_replacement_request() {
    let mut pending = PendingBootstrap::new(false).await;
    let stale = pending.history().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.connect(pending.peer).await;
    let current = pending.history().await;
    stale.send(Ok(pending.manifest())).unwrap();
    pending.quiet().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    current.send(Ok(pending.manifest())).unwrap();
    let (_, _, _reply) = pending.state().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 1);
    let mut metrics = String::new();
    pending.sync_status.render_metrics(&mut metrics);
    assert!(metrics.contains("neutrin0_sync_bootstrap_requests_total{kind=\"history\"} 2"));
    assert!(metrics.contains(
        "neutrin0_sync_bootstrap_results_total{kind=\"history\",outcome=\"cancelled\"} 1"
    ));
    assert!(
        metrics
            .contains("neutrin0_sync_bootstrap_results_total{kind=\"history\",outcome=\"ok\"} 1")
    );
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_failed_fragment_provider_fails_over_without_restarting_manifest() {
    let mut pending = PendingBootstrap::new(false).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (first, items, reply) = pending.state().await;
    let second = random_peer();
    pending.connect(second).await;
    bootstrap_unavailable(reply);
    let (replacement, replacement_items, failed) = pending.state().await;
    assert_eq!(replacement, second);
    assert_ne!(replacement, first);
    assert_eq!(replacement_items, items);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 1);
    bootstrap_unavailable(failed);
    // A second provider may supply a manifest once after both copies of the old
    // root fail. It cannot endlessly repeat a failed endpoint.
    let manifest = pending.history().await;
    bootstrap_unavailable(manifest);
    pending.quiet().await;
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_unavailable_at_genesis_resumes_source_replay_without_polling() {
    let mut pending = PendingBootstrap::with_origin(false, true).await;
    bootstrap_unavailable(pending.history().await);
    // Ordinary sync owns the chain again; with no consensus target here it
    // has nothing to fetch.
    while let Ok(Some(command)) = timeout(Duration::from_secs(1), pending.commands.recv()).await {
        assert!(
            matches!(command, NetworkCommand::Subscribe(_)),
            "unexpected {command:?}"
        );
    }
    assert!(!pending.backend.inner.lock().unwrap().bootstrap_fetching);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_disconnect_at_genesis_releases_fetching_and_resumes_raw_sync() {
    let mut pending = PendingBootstrap::with_origin(false, true).await;
    let _in_flight = pending.history().await;
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.quiet().await;
    assert!(!pending.backend.inner.lock().unwrap().bootstrap_fetching);

    // A no-prefix status independently releases a leftover genesis-only fetch
    // barrier, so ordinary source replay can start without a bootstrap provider.
    pending.backend.inner.lock().unwrap().bootstrap_fetching = true;
    pending.status.finalized_chunk_id = None;
    pending.status.checkpoint_hash = [0; 32];
    let source = random_peer();
    pending.connect(source).await;
    while let Ok(Some(command)) = timeout(Duration::from_secs(1), pending.commands.recv()).await {
        assert!(
            matches!(command, NetworkCommand::Subscribe(_)),
            "unexpected {command:?}"
        );
    }
    assert!(!pending.backend.inner.lock().unwrap().bootstrap_fetching);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_disconnect_preserves_a_nonzero_trusted_anchor_barrier() {
    let mut pending = PendingBootstrap::new(false).await;
    let _in_flight = pending.history().await;
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.quiet().await;
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);

    pending.status.finalized_chunk_id = None;
    pending.status.checkpoint_hash = [0; 32];
    pending.connect(random_peer()).await;
    pending.quiet().await;
    assert!(pending.backend.inner.lock().unwrap().bootstrap_fetching);
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 0);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_manifest_that_cannot_be_sent_does_not_enter_the_fetch_barrier() {
    let mut pending = PendingBootstrap::unconnected(false, false);
    pending
        .events
        .send(NetworkEvent::PeerConnected(pending.peer))
        .await
        .unwrap();
    let (owner, request, reply) = pending.next().await;
    assert_eq!(owner, pending.peer);
    assert!(matches!(request, RpcRequest::Status(_)));
    // The network service stops accepting commands before the manifest request.
    pending.commands.close();
    reply.send(Ok(RpcResponse::Status(pending.status))).unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    // The manifest was attempted but never sent: no request is outstanding,
    // so neither the driver nor the backend may hold the fetch barrier.
    let mut metrics = String::new();
    pending.sync_status.render_metrics(&mut metrics);
    assert!(metrics.contains("neutrin0_sync_bootstrap_requests_total{kind=\"history\"} 1"));
    assert!(metrics.contains(
        "neutrin0_sync_bootstrap_results_total{kind=\"history\",outcome=\"transport\"} 1"
    ));
    assert!(metrics.contains("neutrin0_sync_bootstrap_waiting 0"));
    assert!(!pending.backend.inner.lock().unwrap().bootstrap_fetching);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_restores_connection_generations_and_finalizes_the_next_chunk() {
    let mut pending = PendingBootstrap::new(false).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (_, _, state_reply) = pending.state().await;
    pending.backend.inner.lock().unwrap().full_chunk_size = Some(2);
    state_reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse::default())))
        .unwrap();
    let (_, request, status_reply) = pending.next().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    let mut first = sample_block(11, 11);
    first.header.parent_hash = pending.proof.end().block_hash;
    let mut second = sample_block(12, 12);
    second.header.parent_hash = first.hash();
    let blocks = vec![first, second];
    let mut status = pending.status;
    status.head_height = 12;
    status.head_block_hash = blocks[1].hash();
    status.finalized_chunk_id = Some(5);
    status.finalized_chunk_hash = [0xCC; 32];
    status_reply.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, block_reply) =
        next_full_sync_payload_request(&mut pending.commands, status).await;
    assert!(
        matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 11 && range.count == 2)
    );
    block_reply
        .send(Ok(RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: proven_all(&blocks),
            candidates: Vec::new(),
        })))
        .unwrap();
    let (request, chunk_reply) =
        next_full_sync_payload_request(&mut pending.commands, status).await;
    assert!(matches!(request, RpcRequest::ChunkProofById(range) if range.chunk_ids == vec![5]));
    let mut chunk = sample_chunk_proof(5, 12);
    chunk.public_inputs.end_block_hash = blocks[1].hash();
    chunk_reply
        .send(Ok(RpcResponse::ChunkProofById(ChunkProofByIdResponse {
            proofs: vec![chunk],
        })))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(pending.backend.chunk_proof_imports(), vec![5]);
    assert_eq!(pending.backend.inner.lock().unwrap().status.head_height, 12);
    pending.stop().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn bootstrap_success_preserves_nonce_against_an_older_disconnected_response() {
    let mut pending = PendingBootstrap::new(false).await;
    let old = pending.history().await;
    let old_payload = pending.manifest();
    pending
        .events
        .send(NetworkEvent::PeerDisconnected(pending.peer))
        .await
        .unwrap();
    pending.connect(pending.peer).await;
    pending
        .history()
        .await
        .send(Ok(pending.manifest()))
        .unwrap();
    let (_, _, reply) = pending.state().await;
    reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse::default())))
        .unwrap();
    let (_, request, status_reply) = pending.next().await;
    assert!(matches!(request, RpcRequest::Status(_)));
    // The next endpoint lies beyond the window peers retain, so the installed
    // node snapshots again rather than syncing sequentially.
    let end = &mut pending.proof.statement.statement.end;
    end.next_chunk_id = 14;
    end.height = 28;
    end.slot = 28;
    end.block_hash = [11; 32];
    end.state_root = [10; 32];
    pending.status.checkpoint_hash = pending.proof.end_checkpoint().hash();
    pending.status.finalized_chunk_id = Some(13);
    pending.status.head_height = 28;
    pending.backend.inner.lock().unwrap().bootstrap_origin = Some(pending.origin);
    status_reply
        .send(Ok(RpcResponse::Status(pending.status)))
        .unwrap();
    let current = pending.history().await;
    old.send(Ok(old_payload)).unwrap();
    pending.quiet().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 1);
    current.send(Ok(pending.manifest())).unwrap();
    let (_, _, _reply) = pending.state().await;
    assert_eq!(pending.backend.inner.lock().unwrap().bootstrap_imports, 2);
    pending.stop().await;
}

#[path = "driver_loop/bft_candidate_backfill.rs"]
mod bft_candidate_backfill;

#[path = "driver_loop/bft_round_recovery.rs"]
mod bft_round_recovery;

#[path = "driver_loop/signed_artifact_backfill.rs"]
mod signed_artifact_backfill;

#[tokio::test(start_paused = true)]
async fn sequential_full_sync_observer_tracks_authenticated_progress_and_new_targets() {
    let backend = MockBackend::default();
    let local = LocalProgress {
        finalized_chunk_id: Some(0),
        head_height: 2,
        proven_height: 2,
        ..LocalProgress::default()
    };
    let peer_status = Status {
        finalized_chunk_id: Some(0),
        head_height: 2,
        ..Status::default()
    };
    {
        let mut state = backend.inner.lock().unwrap();
        state.full_chunk_size = Some(2);
        state.chunk_proof_imports.push(0);
        state.status = peer_status;
        state.local_progress_override = Some(local);
    }
    let (commands, mut requests) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend.clone()),
        local,
        commands,
        event_rx,
    );
    let status = driver.status();
    assert!(status.is_syncing());
    assert!(status.awaiting_first_peer());
    let runner = tokio::spawn(driver.run());
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (request, reply) = next_full_sync_request(&mut requests).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    reply.send(Ok(RpcResponse::Status(peer_status))).unwrap();
    assert_no_full_sync_payload_request(&mut requests, peer_status).await;
    assert!(
        !status.is_syncing(),
        "authenticated head/proofs/finality are caught up even while the FSM stays Init"
    );
    assert!(!status.awaiting_first_peer());
    let mut metrics = String::new();
    status.render_metrics(&mut metrics);
    assert!(metrics.contains("neutrin0_sync_phase{phase=\"following\"} 1"));

    let ahead = Status {
        finalized_chunk_id: Some(1),
        head_height: 4,
        ..peer_status
    };
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (_, reply) = next_full_sync_request(&mut requests).await;
    reply.send(Ok(RpcResponse::Status(ahead))).unwrap();
    let (request, _reply) = next_full_sync_payload_request(&mut requests, ahead).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(_)));
    tokio::task::yield_now().await;
    assert!(
        status.is_syncing(),
        "a later target makes the observer report backfill again"
    );
    assert!(!status.awaiting_first_peer());
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn sequential_full_sync_unknown_target_cannot_report_following() {
    let backend = MockBackend::default();
    let local = LocalProgress {
        finalized_chunk_id: Some(0),
        head_height: 2,
        proven_height: 2,
        ..LocalProgress::default()
    };
    let peer_status = Status {
        finalized_chunk_id: Some(0),
        head_height: 2,
        ..Status::default()
    };
    {
        let mut state = backend.inner.lock().unwrap();
        state.full_chunk_size = Some(2);
        state.chunk_proof_imports.push(0);
        state.status = peer_status;
        state.local_progress_override = Some(local);
    }
    let (commands, mut requests) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend.clone()),
        local,
        commands,
        event_rx,
    );
    let status = driver.status();
    let runner = tokio::spawn(driver.run());
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (_, reply) = next_full_sync_request(&mut requests).await;
    reply.send(Ok(RpcResponse::Status(peer_status))).unwrap();
    assert_no_full_sync_payload_request(&mut requests, peer_status).await;
    assert!(!status.is_syncing());
    backend.inner.lock().unwrap().full_chunk_size = None;
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (_, reply) = next_full_sync_request(&mut requests).await;
    reply.send(Ok(RpcResponse::Status(peer_status))).unwrap();
    assert_no_full_sync_payload_request(&mut requests, peer_status).await;
    assert!(
        status.is_syncing(),
        "an unknown authenticated target is conservative"
    );
    assert!(!status.awaiting_first_peer());
    let mut metrics = String::new();
    status.render_metrics(&mut metrics);
    assert!(metrics.contains("neutrin0_sync_progress_available 1"));
    assert!(metrics.contains("neutrin0_sync_full_chunk_target_available 0"));
    assert!(!metrics.contains("neutrin0_sync_full_chunk_consensus_target{"));
    {
        let mut state = backend.inner.lock().unwrap();
        state.full_chunk_size = Some(2);
        state.local_progress_error = true;
    }
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (_, reply) = next_full_sync_request(&mut requests).await;
    reply.send(Ok(RpcResponse::Status(peer_status))).unwrap();
    assert_no_full_sync_payload_request(&mut requests, peer_status).await;
    metrics.clear();
    status.render_metrics(&mut metrics);
    assert!(status.is_syncing());
    assert!(metrics.contains("neutrin0_sync_progress_available 0"));
    assert!(metrics.contains("neutrin0_sync_full_chunk_target_available 1"));
    assert!(!metrics.contains("neutrin0_sync_fsm_progress{"));
    drop(events);
    runner.await.unwrap();
}

#[path = "driver_loop/transaction_repair.rs"]
mod transaction_repair;

#[path = "driver_loop/network_recovery.rs"]
mod network_recovery;

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)] // Bounded successor download followed by higher-priority predecessor finality.
async fn certified_execution_backfill_stops_at_its_window_and_prioritizes_finality() {
    let backend = MockBackend::default();
    {
        let mut state = backend.inner.lock().unwrap();
        state.full_chunk_size = Some(2);
        state.certified_sync_height = Some(4);
    }
    let observer = backend.clone();
    let (commands, mut received) = mpsc::channel(64);
    let (events, event_rx) = mpsc::channel(16);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        commands,
        event_rx,
    );
    let runner = tokio::spawn(driver.run());
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let mut branch = Vec::new();
    let mut parent = [0; 32];
    for height in 1..=6 {
        let mut block = sample_block(height, height);
        block.header.parent_hash = parent;
        parent = block.hash();
        branch.push(block);
    }
    let mut proof_ready = false;
    let mut order = Vec::new();
    for _ in 0..16 {
        let (request, reply) = next_full_sync_request(&mut received).await;
        let response = match request {
            RpcRequest::Status(_) => RpcResponse::Status(Status {
                head_height: 6,
                head_block_hash: branch.last().unwrap().hash(),
                finalized_chunk_id: proof_ready.then_some(0),
                finalized_chunk_hash: [0xCC; 32],
                ..Default::default()
            }),
            RpcRequest::BlocksByRange(query) => {
                assert_eq!((query.start_height, query.count), (1, 4));
                order.push("blocks");
                proof_ready = true;
                RpcResponse::BlocksByRange(BlocksByRangeResponse {
                    blocks: proven_all(&branch[..4]),
                    candidates: Vec::new(),
                })
            }
            RpcRequest::ChunkProofById(query) => {
                assert_eq!(query.chunk_ids, vec![0]);
                assert_eq!(order, ["blocks"]);
                let mut proof = sample_chunk_proof(0, 2);
                proof.public_inputs.end_block_hash = branch[1].hash();
                reply
                    .send(Ok(RpcResponse::ChunkProofById(ChunkProofByIdResponse {
                        proofs: vec![proof],
                    })))
                    .unwrap();
                break;
            }
            other => panic!("unexpected bounded sync request {other:?}"),
        };
        reply.send(Ok(response)).unwrap();
    }
    timeout(Duration::from_secs(1), async {
        while observer.chunk_proof_imports().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(observer.chunk_proof_imports(), vec![0]);
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_running_node_snapshots_only_beyond_the_window_its_peers_retain() {
    // This node has finalized its first chunk and trusts its own boundary.
    let mut pending = PendingBootstrap::unconnected(false, false);
    pending
        .backend
        .inner
        .lock()
        .unwrap()
        .status
        .finalized_chunk_id = Some(0);
    let bootstrap_request = |request: &RpcRequest| matches!(request, RpcRequest::HistoryProof(request) if request.bootstrap);
    // A peer within the retained window is caught up with sequentially.
    pending.status.finalized_chunk_id = Some(8);
    pending.connect(pending.peer).await;
    while let Ok(Some(command)) = timeout(Duration::from_secs(1), pending.commands.recv()).await {
        if let NetworkCommand::SendRpcRequest { request, .. } = command {
            assert!(!bootstrap_request(&request), "snapshot within the window");
        }
    }
    // One beyond it may have pruned what sequential sync needs: snapshot.
    pending.status.finalized_chunk_id = Some(9);
    let far = random_peer();
    pending.connect(far).await;
    loop {
        let (owner, request, _reply) = pending.next().await;
        if bootstrap_request(&request) {
            assert_eq!(owner, far);
            break;
        }
    }
    pending.stop().await;
}

async fn next_response(
    commands: &mut mpsc::Receiver<NetworkCommand>,
    within: Duration,
) -> (u64, RpcResponse) {
    loop {
        match timeout(within, commands.recv()).await {
            Ok(Some(NetworkCommand::SendRpcResponse {
                inbound_id,
                response,
            })) => return (inbound_id.raw, response),
            Ok(Some(_)) => {}
            other => panic!("expected a response, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn slow_data_queries_neither_stall_the_driver_nor_let_one_peer_take_every_slot() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().slow_ranges = true;
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend.clone()),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());
    let peers: Vec<_> = (0..5).map(|_| random_peer()).collect();
    for peer in &peers {
        event_tx
            .send(NetworkEvent::PeerConnected(*peer))
            .await
            .unwrap();
    }
    let request = |peer, raw, request| NetworkEvent::RpcRequestReceived {
        peer,
        inbound_id: RpcInboundId {
            protocol: match &request {
                RpcRequest::Status(_) => RpcProtocol::Status,
                _ => RpcProtocol::BlocksByRange,
            },
            raw,
        },
        request,
    };
    let range = || {
        RpcRequest::BlocksByRange(neutrin0_network::rpc::BlocksByRangeRequest {
            start_height: 1,
            count: 1,
            head_block_hash: [0; 32],
        })
    };
    // The first peer asks twice; four peers fill the shared slots between them.
    event_tx.send(request(peers[0], 1, range())).await.unwrap();
    event_tx.send(request(peers[0], 2, range())).await.unwrap();
    for (raw, peer) in (3..).zip(&peers[1..]) {
        event_tx.send(request(*peer, raw, range())).await.unwrap();
    }
    // The driver keeps answering while they run.
    event_tx
        .send(request(peers[0], 7, RpcRequest::Status(Status::default())))
        .await
        .unwrap();
    let (raw, status) = next_response(&mut cmd_rx, Duration::from_secs(1)).await;
    assert_eq!(raw, 7);
    assert!(matches!(status, RpcResponse::Status(_)));
    // The first peer's second query and the fifth peer's wait their turn and
    // are refused as busy once the wait runs out.
    let mut busy = Vec::new();
    for _ in 0..2 {
        let (raw, response) = next_response(&mut cmd_rx, Duration::from_secs(10)).await;
        assert!(matches!(
            response,
            RpcResponse::Error {
                error: neutrin0_network::rpc::RpcFailure::Unavailable(_),
                ..
            }
        ));
        busy.push(raw);
    }
    busy.sort_unstable();
    assert_eq!(busy, [2, 6]);
    // Reconnecting does not grant a peer a second slot while its query runs.
    event_tx
        .send(NetworkEvent::PeerDisconnected(peers[1]))
        .await
        .unwrap();
    event_tx
        .send(NetworkEvent::PeerConnected(peers[1]))
        .await
        .unwrap();
    event_tx.send(request(peers[1], 8, range())).await.unwrap();
    let (raw, response) = next_response(&mut cmd_rx, Duration::from_secs(10)).await;
    assert_eq!(raw, 8);
    assert!(matches!(response, RpcResponse::Error { .. }));
    backend.range_gate.0.add_permits(4);
    let mut served = Vec::new();
    for _ in 0..4 {
        let (raw, page) = next_response(&mut cmd_rx, Duration::from_secs(1)).await;
        assert!(matches!(page, RpcResponse::BlocksByRange(_)));
        served.push(raw);
    }
    served.sort_unstable();
    assert_eq!(served, [1, 3, 4, 5]);
    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn checkpoint_notices_of_nothing_new_are_neither_relayed_nor_acted_on() {
    use neutrin0_network::libp2p::gossipsub::{MessageAcceptance, MessageId};
    let backend = MockBackend::default();
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());
    let peer = random_peer();
    event_tx
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let mut verdict = async |chunk_count: u64| {
        let notice = neutrin0_network::rpc::CheckpointAnnouncement {
            chunk_count,
            checkpoint_hash: [7; 32],
        };
        event_tx
            .send(NetworkEvent::GossipMessage {
                topic: neutrin0_network::Topic::Checkpoints,
                data: borsh::to_vec(&notice).unwrap(),
                propagation_source: peer,
                message_id: MessageId::from(chunk_count.to_be_bytes().to_vec()),
            })
            .await
            .unwrap();
        loop {
            match timeout(Duration::from_secs(1), cmd_rx.recv()).await {
                Ok(Some(NetworkCommand::ReportGossipValidation { acceptance, .. })) => {
                    return acceptance;
                }
                Ok(Some(_)) => {}
                other => panic!("expected a verdict, got {other:?}"),
            }
        }
    };
    // Local finality is at zero chunks: an announcement of zero is not news.
    assert_eq!(verdict(0).await, MessageAcceptance::Ignore);
    assert_eq!(verdict(1).await, MessageAcceptance::Accept);
    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_program_whose_bytes_fail_their_identity_is_fetched_from_another_peer() {
    let backend = MockBackend::default();
    let item = StateItem::runtime([5; 32]);
    backend.inner.lock().unwrap().wanted_program = Some(item);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<NetworkCommand>(32);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        cmd_tx,
        event_rx,
    );
    let handle = tokio::spawn(driver.run());
    for _ in 0..2 {
        event_tx
            .send(NetworkEvent::PeerConnected(random_peer()))
            .await
            .unwrap();
    }
    let mut fetch = async || loop {
        match timeout(Duration::from_secs(30), cmd_rx.recv()).await {
            Ok(Some(NetworkCommand::SendRpcRequest {
                peer,
                request: RpcRequest::StateByRoot(_),
                response_tx,
            })) => return (peer, response_tx),
            Ok(Some(_)) => {}
            other => panic!("expected a program fetch, got {other:?}"),
        }
    };
    let (first, reply) = fetch().await;
    reply
        .send(Ok(RpcResponse::StateByRoot(StateByRootResponse {
            entries: neutrin0_consensus_types::bootstrap::StateEntries::new(vec![
                neutrin0_consensus_types::bootstrap::StateEntry {
                    item,
                    total_len: 4,
                    bytes: neutrin0_primitives::BoundedBytes::new(b"\0asm".to_vec()).unwrap(),
                },
            ])
            .unwrap(),
        })))
        .unwrap();
    // The backend asks for the same artifact from its start again: whoever
    // served it backs off and another peer is asked.
    let (second, _reply) = fetch().await;
    assert_ne!(first, second);
    drop(event_tx);
    handle.await.unwrap();
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_lone_contradicting_peer_cannot_hold_a_light_client_back() {
    let backend = MockBackend::default();
    backend.set_advance(5, 10);
    let proof = sample_history_proof();
    let (events, mut commands, runner) = sampling_light_driver(&backend);
    // A peer contradicts the client's own endpoint and never backs it up.
    let mut lie = advertising(&proof);
    lie.finalized_chunk_id = Some(0);
    lie.checkpoint_hash = [77; 32];
    sample(&events, &mut commands, random_peer(), lie).await;
    let (_, check, _held) = next_history_request(&mut commands).await.unwrap();
    assert_eq!((check.anchor_chunks, check.end_chunks), (0, 1));
    // A quorum still moves the client while that check is outstanding.
    for _ in 0..3 {
        sample(&events, &mut commands, random_peer(), advertising(&proof)).await;
    }
    let (_, advance, response) = next_history_request(&mut commands).await.unwrap();
    assert_eq!((advance.anchor_chunks, advance.end_chunks), (1, 5));
    response.send(Ok(history_reply(&proof))).unwrap();
    tokio::task::yield_now().await;
    assert!(backend.rpc_calls().contains(&"history_import".to_owned()));
    drop(events);
    runner.await.unwrap();
}
