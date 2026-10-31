//! Event-driven complete proving with exact BFT quorum fencing.

mod chunk_proof;

use super::{BftQuorumIdentity, ChainBackend, SyncBackendError, rejected};
use neutrin0_consensus_engine::ProposerKey;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use std::sync::Arc;
use tracing::{debug, info, warn};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Automatic consensus work requires a validator key or an explicit prover opt-in.
    pub(super) fn proves_consensus(&self) -> bool {
        !self.is_light() && (self.prove_foreign_blocks() || self.local_voter().is_some())
    }

    /// Reporters generate evidence on demand without pre-proving consensus facts.
    pub(super) fn proves_evidence(&self) -> bool {
        self.proves_consensus() || (!self.is_light() && self.reporter_recipient().is_some())
    }

    /// Block program of the embedded set, also used by verification-only nodes.
    pub(super) fn block_program(&self) -> Option<[u32; 8]> {
        self.proof_system
            .programs()
            .map(|programs| programs.execution.block)
    }

    /// Fact program of the embedded set.
    pub(super) fn fact_program(&self) -> Option<[u32; 8]> {
        self.proof_system
            .programs()
            .map(|programs| programs.execution.fact)
    }

    pub(super) fn ready_consensus_quorum(&self) -> Option<BftQuorumIdentity> {
        self.block_program()?;
        self.with_engine(|engine| {
            engine.execution_quorum_identity(engine.finalized_next_chunk_id())
        })
    }

    pub(super) fn handle_quorum_reached(&self, identity: BftQuorumIdentity) {
        if self.bootstrap_pending() || self.is_light() || self.block_program().is_none() {
            return;
        }
        if let Err(error) = self.certify_quorum_execution(identity) {
            warn!(?identity, %error, "execution certification failed");
            return;
        }
        if let Some(lag) = self.metrics.execution.certified(identity.chunk_id) {
            info!(
                chunk_id = identity.chunk_id,
                bft_secs = lag.bft.as_secs_f64(),
                since_tail_slot_start_secs = lag.since_slot_start.map(|d| d.as_secs_f64()),
                stall_secs = lag.stall.map(|d| d.as_secs_f64()),
                "execution certificate complete"
            );
        }
        self.sync_programs();
        if !self.proves_consensus() {
            return;
        }
        let voter = self.local_voter();
        let policy = *self.proving_policy.lock().expect("proving policy");
        let (ready, certified_at, slot_secs) =
            self.chunk_proof_readiness(identity, voter.as_deref(), policy.chunk_fallback_secs);
        if !ready {
            return;
        }
        // Block proofs go first (design 08): a running chunk proof
        // cannot be preempted and takes minutes, while production waits on
        // block proofs that take seconds. The deferral is bounded by one slot
        // so finality is never starved; every BFT tick re-evaluates it.
        if policy.block_proof_priority
            && self.block_proofs_defer_chunk_proof(identity, certified_at, slot_secs)
        {
            return;
        }
        self.start_consensus_proof(identity);
    }

    /// Install the quorum's certificate and certify the execution it covers,
    /// unless another node's certificate already did.
    fn certify_quorum_execution(
        &self,
        identity: BftQuorumIdentity,
    ) -> Result<(), SyncBackendError> {
        let executor = self.replay_executor_snapshot();
        self.with_live_engine_mut(|engine| {
            if engine.execution_quorum_identity(identity.chunk_id) != Some(identity) {
                return Err(SyncBackendError::NotAvailable(
                    "BFT quorum changed before certification".into(),
                ));
            }
            if engine.certified_execution_witness().is_none() {
                let certificate = engine
                    .bft_session(identity.chunk_id)
                    .and_then(neutrin0_consensus_engine::BftSession::certificate)
                    .ok_or_else(|| {
                        SyncBackendError::NotAvailable("complete certificate unavailable".into())
                    })?;
                let mut prepared = engine
                    .prepare_bft_consensus_chunk(identity.chunk_id, self.proof_system.as_ref())
                    .map_err(rejected)?;
                engine
                    .install_finality_certificate(&mut prepared, certificate)
                    .map_err(rejected)?;
                engine
                    .certify_execution_chunk(
                        &prepared,
                        self.proof_system.as_ref(),
                        executor.as_deref(),
                    )
                    .map_err(rejected)?;
            }
            Ok(())
        })
    }

    /// Whether this node proves the certified chunk now, with the certification
    /// time and slot length the deferral rule measures against.
    fn chunk_proof_readiness(
        &self,
        identity: BftQuorumIdentity,
        voter: Option<&ProposerKey>,
        chunk_fallback_secs: u64,
    ) -> (bool, u64, u64) {
        self.with_engine(|engine| {
            if engine.execution_quorum_identity(identity.chunk_id) != Some(identity) {
                return (false, 0, 0);
            }
            let preferred = voter.is_some_and(|voter| {
                leads_next_chunk(engine, identity.chunk_id, voter.public_key_bytes())
            });
            let since = engine
                .execution_certified_at_secs()
                .unwrap_or_else(crate::now_secs);
            (
                crate::producer::fallback_ready(
                    preferred,
                    since,
                    chunk_fallback_secs,
                    crate::now_secs(),
                ),
                since,
                engine.chain_spec().consensus.slot_duration_secs,
            )
        })
    }

    fn block_proofs_defer_chunk_proof(
        &self,
        identity: BftQuorumIdentity,
        certified_at: u64,
        slot_secs: u64,
    ) -> bool {
        let pending = !self.pending_block_proofs(1, 1, |_| false).is_empty();
        if crate::producer::chunk_proof_deferred(
            true,
            pending,
            certified_at,
            slot_secs,
            crate::now_secs(),
        ) {
            debug!(
                chunk_id = identity.chunk_id,
                "chunk proof waits for this node's pending block proofs"
            );
            return true;
        }
        false
    }

    /// Wait for completed work rather than polling a long-running prover.
    /// The node runner starts one worker and aborts it during shutdown.
    pub async fn run_consensus_proof_notifications(self: Arc<Self>) {
        loop {
            self.consensus_proof_notify.notified().await;
            self.drain_completed_consensus_proof().await;
        }
    }

    /// Drive BFT round deadlines independently of block-production slots.
    /// The node runner starts one validator clock and aborts it during shutdown.
    pub async fn run_bft_round_timeouts(self: Arc<Self>) {
        let mut clock = tokio::time::interval(std::time::Duration::from_secs(1));
        clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            clock.tick().await;
            self.tick_bft_round_timeouts(crate::now_secs()).await;
        }
    }

    /// Resume BFT when a successor's Block proofs completed before predecessor finality.
    pub(super) async fn resume_proven_successor(&self) {
        let height = self.with_engine(|engine| {
            engine
                .finalized_next_chunk_id()
                .checked_add(1)
                .and_then(|count| count.checked_mul(engine.chain_spec().consensus.chunk_size))
        });
        if let Some(height) = height {
            self.maybe_open_bft_session_for_height(height).await;
        }
    }
}

/// Whether `pubkey` leads round zero of the chunk after `chunk_id` under the
/// committee its certificate seats (design 08). That leader ratifies any
/// valid proof of `chunk_id` and rationally its own, so it proves at once
/// while every other node falls back.
fn leads_next_chunk<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    chunk_id: u64,
    pubkey: &[u8; 48],
) -> bool {
    // Without a certificate the current committee and seed are the closest
    // guess; it only decides who proves first.
    let (successors, seed) = engine
        .certified_successor()
        .unwrap_or_else(|| (engine.active_validator_set(), engine.finalized_seed()));
    neutrin0_consensus_types::bft_leader(
        engine.chain_spec().chain_id,
        chunk_id.saturating_add(1),
        0,
        &seed,
        successors,
    )
    .and_then(|index| successors.get(index as usize))
    .is_some_and(|validator| validator.pubkey == *pubkey)
}
