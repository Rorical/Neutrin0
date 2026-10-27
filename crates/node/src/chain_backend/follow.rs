//! Import of complete publications (design 07): each `ProvenBlock` carries
//! the block, the bytes of its receipt and the write set of its execution.
//!
//! A proof-following node verifies the receipt and applies the writes; an
//! executing node re-executes the body, verifies the receipt and checks the
//! published writes against its own. Either way the engine judges the bundle
//! as a unit, and a publication missing any part never becomes a block.

mod orphans;
mod receipt_budget;

pub(super) use orphans::OrphanReceipts;

use super::{ChainBackend, availability};
use neutrin0_consensus_engine::{ImportError, StateSource};
use neutrin0_consensus_types::ProvenBlock;
use neutrin0_primitives::Height;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_sync::{HeadersImported, ReceiptsImported, SyncBackendError};
use orphans::Source;
pub(super) use receipt_budget::ReceiptBudget;
use std::sync::Arc;
use std::sync::atomic::Ordering;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Import peer blocks from verified receipts and state diffs instead of
    /// executing their bodies. Production, queries and admission checks keep
    /// using the installed executor.
    ///
    /// # Errors
    /// Returns an error for a proof-only light node.
    pub fn enable_proof_follow(&self) -> Result<(), String> {
        if self.is_light() {
            return Err("a light client cannot follow receipts".to_owned());
        }
        self.with_engine_mut(|engine| engine.set_state_source(StateSource::ReceiptDiffs));
        self.proof_follow.store(true, Ordering::Release);
        Ok(())
    }

    /// Whether peer blocks are imported from receipts and diffs.
    pub fn is_proof_follow(&self) -> bool {
        self.proof_follow.load(Ordering::Acquire)
    }

    /// Executor for peer imports and branch replay: none while following
    /// receipts, so the engine applies and replays retained diffs.
    pub(super) fn replay_executor_snapshot(&self) -> Option<Arc<dyn ErasedBlockExecutor>> {
        if self.is_proof_follow() {
            None
        } else {
            self.block_executor_snapshot()
        }
    }

    /// Import complete publications in order. The first failure stops the
    /// batch; earlier bundles stay imported.
    pub(super) async fn import_proven_blocks(
        &self,
        blocks: Vec<ProvenBlock>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let mut last = None;
        let mut heights = Vec::new();
        for bundle in blocks {
            let height = bundle.block.header.height;
            last = Some(self.import_peer_bundle(&bundle).await?);
            heights.push(height);
        }
        self.open_bft_sessions_for(heights).await;
        last.ok_or_else(|| SyncBackendError::Rejected("empty block batch".to_owned()))
    }

    /// Authorize and import one publication. The canonical receipt envelope
    /// is derived locally so the exact bytes feed signed-artifact retention
    /// whatever the verdict. A header whose VRF claim fails is only refused:
    /// it can never become canonical, so it is not an offence.
    async fn import_peer_bundle(
        &self,
        bundle: &ProvenBlock,
    ) -> Result<HeadersImported, SyncBackendError> {
        let block = &bundle.block;
        self.observe_and_authorize(block).await?;
        let proof = self.with_engine(|engine| {
            let state_root_before = engine
                .state_root_before(&block.header)
                .map_err(|error| SyncBackendError::Storage(error.to_string()))?
                .ok_or_else(|| {
                    SyncBackendError::ChainBehind("parent of the published block is unknown".into())
                })?;
            engine
                .canonical_block_proof(&block.header, state_root_before, bundle.proof_bytes.clone())
                .map_err(Self::map_import_err)
        })?;
        let verdict_token = self.begin_block_verdict(availability::block_proof_source_id(&proof));
        let executor = self.replay_executor_snapshot();
        let result = self.with_live_engine_mut(|engine| {
            Ok(engine.import_proven_block(bundle, self.proof_system.as_ref(), executor.as_deref()))
        })?;
        self.retain_imported_proof_source(&proof, result.is_ok(), verdict_token)
            .await;
        self.collect_contradicting_receipts();
        result
            .map(|outcome| self.after_block_import(block, &outcome))
            .map_err(Self::map_import_err)
    }

    /// Open BFT sessions for chunks that `heights` may have completed: a
    /// validator votes once every block of the next chunk is proven locally.
    pub(super) async fn open_bft_sessions_for(&self, heights: Vec<Height>) {
        let chunk_size = self.chunk_size().max(1);
        let mut chunks = std::collections::BTreeSet::new();
        for height in heights {
            if height > 0 && chunks.insert((height - 1) / chunk_size) {
                self.maybe_open_bft_session_for_height(height).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Candidates and receipts (design 08)
// ---------------------------------------------------------------------------

/// How a receipt was disposed of.
enum ReceiptDisposition {
    /// It proved a candidate at this height.
    Proven(Height),
    /// Its block is unknown here; kept for the orphan window.
    Buffered,
    /// The proposer's own receipt of a block already proven by another;
    /// retained and relayed because selection prefers it.
    Relayed,
    /// Nothing changed: its block was already proven, or is stale.
    Duplicate,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Import candidate publications in order. The first failure stops the
    /// batch; earlier candidates stay imported. Receipts that arrived before
    /// their block are applied as soon as the block is in.
    pub(super) async fn import_candidates(
        &self,
        candidates: Vec<neutrin0_consensus_types::CandidateBlock>,
    ) -> Result<HeadersImported, SyncBackendError> {
        let mut last = None;
        for candidate in candidates {
            last = Some(self.import_peer_candidate(&candidate).await?);
        }
        last.ok_or_else(|| SyncBackendError::Rejected("empty candidate batch".to_owned()))
    }

    /// Authorize and import one candidate: header and body admission, the
    /// write-set root check (or re-execution on an executing node), then the
    /// receipts kept for it.
    async fn import_peer_candidate(
        &self,
        candidate: &neutrin0_consensus_types::CandidateBlock,
    ) -> Result<HeadersImported, SyncBackendError> {
        let block = &candidate.block;
        self.observe_and_authorize(block).await?;
        let executor = self.replay_executor_snapshot();
        let result = self.with_live_engine_mut(|engine| {
            Ok(engine.import_candidate_block(candidate, executor.as_deref()))
        })?;
        match result {
            Ok(outcome) => {
                let imported = self.after_block_import(block, &outcome);
                self.retry_orphan_receipts(&block.hash()).await;
                Ok(imported)
            }
            // Design 08: results the block's execution does not produce may
            // be an invalid execution claim; prove the honest execution. A
            // block this node failed to execute has none to prove.
            Err(diverged)
                if diverged.is_execution_divergence()
                    || matches!(&diverged, ImportError::ExecutionDiverges(inner)
                        if inner.is_execution_divergence()) =>
            {
                self.record_divergent_candidate(block);
                Err(Self::map_import_err(diverged))
            }
            Err(other) => Err(Self::map_import_err(other)),
        }
    }

    /// Verify receipts against their retained headers. A receipt whose block
    /// is unknown is kept for the orphan window; an invalid receipt fails the
    /// batch and is attributable to its source.
    pub(super) async fn import_receipts(
        &self,
        receipts: Vec<neutrin0_consensus_types::BlockReceipt>,
        source: Source,
    ) -> Result<ReceiptsImported, SyncBackendError> {
        let mut imported = ReceiptsImported::default();
        for receipt in receipts {
            match self.import_receipt(&receipt, source).await? {
                ReceiptDisposition::Proven(height) => imported.proven.push(height),
                ReceiptDisposition::Buffered => imported.buffered += 1,
                ReceiptDisposition::Relayed => imported.relayed += 1,
                ReceiptDisposition::Duplicate => {}
            }
        }
        self.open_bft_sessions_for(imported.proven.clone()).await;
        Ok(imported)
    }

    /// Run the proof system's verification of `bytes` against `inputs` on a
    /// blocking worker. Only its caches matter: the import repeats the call.
    async fn verify_receipt_off_lock(
        &self,
        bytes: Vec<u8>,
        inputs: neutrin0_consensus_types::BlockProofPublicInputs,
    ) {
        let proof_system = Arc::clone(&self.proof_system);
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(decoded) = borsh::from_slice::<P::BlockProof>(&bytes) {
                let _ = proof_system.verify_block_statement(&decoded, &inputs);
            }
        })
        .await;
    }

    async fn import_receipt(
        &self,
        receipt: &neutrin0_consensus_types::BlockReceipt,
        source: Source,
    ) -> Result<ReceiptDisposition, SyncBackendError> {
        let envelope = self.with_engine(|engine| {
            let Some(header) = engine
                .store()
                .get_header(&receipt.block_hash)
                .map_err(|error| SyncBackendError::Storage(error.to_string()))?
            else {
                return Ok::<_, SyncBackendError>(None);
            };
            let state_root_before = engine
                .state_root_before(&header)
                .map_err(|error| SyncBackendError::Storage(error.to_string()))?
                .ok_or_else(|| {
                    SyncBackendError::ChainBehind("parent of the receipt's block is unknown".into())
                })?;
            engine
                .canonical_block_proof(&header, state_root_before, receipt.proof_bytes.clone())
                .map(Some)
                .map_err(Self::map_import_err)
        })?;
        let Some(proof) = envelope else {
            return Ok(if self.buffer_orphan_receipt(receipt.clone(), source) {
                ReceiptDisposition::Buffered
            } else {
                ReceiptDisposition::Duplicate
            });
        };
        // Verify ahead of the import on a blocking worker: the import below
        // then finds the verdict cached and holds the engine lock only to
        // record it. Each peer has a bounded number of distinct receipts
        // verified per block, so junk from one peer never crowds out another's.
        let needs_verification = self
            .with_engine(|engine| {
                engine.receipt_needs_verification(receipt, self.proof_system.as_ref())
            })
            .map_err(Self::map_import_err)?;
        if needs_verification {
            let bytes = neutrin0_primitives::blake3_256(&receipt.proof_bytes);
            if !self
                .receipt_budget
                .lock()
                .expect("receipt budget poisoned")
                .admit((source, receipt.block_hash), bytes)
            {
                return Ok(ReceiptDisposition::Duplicate);
            }
            self.verify_receipt_off_lock(receipt.proof_bytes.clone(), proof.public_inputs.clone())
                .await;
        }
        let verdict_token = self.begin_block_verdict(availability::block_proof_source_id(&proof));
        let executor = self.replay_executor_snapshot();
        let result = self.with_live_engine_mut(|engine| {
            Ok(engine.import_block_receipt(
                receipt,
                self.proof_system.as_ref(),
                executor.as_deref(),
            ))
        })?;
        // Bytes skipped for a statement already held were never verified, so
        // they earn no verdict and are not retained as a source.
        if !matches!(
            result,
            Ok(neutrin0_consensus_engine::ReceiptOutcome::StatementHeld { .. })
        ) {
            self.retain_imported_proof_source(&proof, result.is_ok(), verdict_token)
                .await;
        }
        self.collect_contradicting_receipts();
        match result.map_err(Self::map_import_err)? {
            neutrin0_consensus_engine::ReceiptOutcome::Proven { height } => {
                Ok(ReceiptDisposition::Proven(height))
            }
            neutrin0_consensus_engine::ReceiptOutcome::AlreadyProven { .. }
            | neutrin0_consensus_engine::ReceiptOutcome::StatementHeld { .. } => {
                Ok(ReceiptDisposition::Duplicate)
            }
            neutrin0_consensus_engine::ReceiptOutcome::ProposerReceipt { .. } => {
                Ok(ReceiptDisposition::Relayed)
            }
        }
    }

    /// Keep a receipt whose block is unknown for `proof_orphan_slots`.
    fn buffer_orphan_receipt(
        &self,
        receipt: neutrin0_consensus_types::BlockReceipt,
        source: Source,
    ) -> bool {
        let (ttl, per_block) = self.with_engine(|engine| {
            let consensus = &engine.chain_spec().consensus;
            (
                std::time::Duration::from_secs(
                    consensus
                        .proof_orphan_slots
                        .saturating_mul(consensus.slot_duration_secs),
                ),
                usize::try_from(consensus.max_receipts_per_block).unwrap_or(usize::MAX),
            )
        });
        self.orphan_receipts.lock().expect("orphan receipts").push(
            receipt,
            source,
            std::time::Instant::now(),
            ttl,
            per_block,
        )
    }

    /// Apply the receipts kept for a block that has just been imported.
    async fn retry_orphan_receipts(&self, block_hash: &neutrin0_primitives::BlockHash) {
        let kept = self
            .orphan_receipts
            .lock()
            .expect("orphan receipts")
            .take(block_hash);
        for (source, receipt) in kept {
            match self.import_receipts(vec![receipt], source).await {
                Err(SyncBackendError::Rejected(reason)) => {
                    // Its source vouched for a receipt that turned out
                    // invalid; its orphans are refused for a while.
                    tracing::debug!(%source, %reason, "buffered receipt rejected once its block arrived");
                    self.orphan_receipts
                        .lock()
                        .expect("orphan receipts")
                        .distrust(source, std::time::Instant::now());
                }
                Err(error) => {
                    tracing::debug!(%source, %error, "buffered receipt not applied once its block arrived");
                }
                Ok(_) => {}
            }
        }
    }

    /// Receipts kept for blocks not held yet.
    pub fn orphan_receipt_count(&self) -> usize {
        self.orphan_receipts.lock().expect("orphan receipts").len()
    }
}
