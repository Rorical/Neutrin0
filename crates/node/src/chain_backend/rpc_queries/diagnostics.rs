//! Public operator diagnostics: sync, BFT sessions and proof work. The local
//! validator's identity, seat and votes are on the management socket.

use std::sync::atomic::Ordering;

use neutrin0_consensus_engine::Engine;
use neutrin0_proof_system::ProofSystem;
use neutrin0_rpc::{
    QueryError,
    types::{BftSessionJson, DiagnosticsJson, HashHex, ProofWorkJson, SyncProgressJson, Wei},
};
use neutrin0_storage::Database;
use neutrin0_sync::SyncStatus;

use super::ChainBackend;
use crate::proof_metrics::ProofStage;

fn sync_progress(status: &SyncStatus) -> SyncProgressJson {
    let progress = status.operator_progress();
    SyncProgressJson {
        phase: progress.phase.into(),
        peers: status.peer_count(),
        syncing: status.is_syncing(),
        awaiting_first_peer: status.awaiting_first_peer(),
        cursor_height: progress.cursor_height,
        target_height: progress.target_height,
        full_chunk_target_height: progress.full_chunk_target_height,
        full_chunk_cursors: progress.full_chunk_cursors,
        bootstrap_target_chunks: progress.bootstrap_target_chunks,
        bootstrap_pending_items: progress.bootstrap_pending_items,
    }
}

fn bft_sessions<DB: Database>(engine: &Engine<DB>) -> Vec<BftSessionJson> {
    engine
        .bft_session_overview()
        .into_iter()
        .map(|session| BftSessionJson {
            chunk_id: session.chunk_id,
            round: session.round,
            stake: session.stake.map(Wei),
            prevote_quorum: session.prevote_quorum,
            precommit_quorum: session.precommit_quorum,
        })
        .collect()
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    fn proof_work(&self) -> Vec<ProofWorkJson> {
        ProofStage::ALL
            .into_iter()
            .map(|stage| ProofWorkJson {
                stage: stage.label().into(),
                waiting: self.metrics.proof_pipeline.budget.waiting(stage),
                running: self.metrics.proof_pipeline.budget.inflight(stage),
            })
            .collect()
    }

    pub(super) fn diagnostics_snapshot(&self) -> Result<DiagnosticsJson, QueryError> {
        let proof_only = self.is_light();
        let bootstrap_pending = self.bootstrap_pending();
        let unavailable = proof_only || bootstrap_pending;
        let light = self.light_health();
        let trust_anchor_expired = light.is_some_and(|health| health.expired);
        let history_conflict = light.is_some_and(|health| health.halted);
        let sync = self.sync_status().map(|status| sync_progress(&status));
        self.with_engine(|engine| {
            Ok(DiagnosticsJson {
                chain_spec_hash: HashHex(self.chain_spec_hash),
                chunk_size: engine.chain_spec().consensus.chunk_size,
                unbonding_delay_blocks: engine.chain_spec().runtime.unbonding_delay_blocks,
                proof_only,
                bootstrap_pending,
                trust_anchor_expired,
                history_conflict,
                storage_pressure: self.storage_pressure(),
                sync,
                bft_sessions: (!unavailable).then(|| bft_sessions(engine)),
                proof_work: self.proof_work(),
                queued_block_proofs: self
                    .metrics
                    .block_proof_queue_pending
                    .load(Ordering::Relaxed),
            })
        })
    }
}
