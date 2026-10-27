//! Local block production and the stale-candidate rule it builds on.

use neutrin0_consensus_engine::{
    Engine, ProductionConfig, ProductionError, ProductionOutcome, ProposerKey,
};
use neutrin0_primitives::Slot;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use tracing::warn;

use super::{ChainBackend, DEFAULT_BODY_TX_BUDGET_BYTES};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Try to produce a block for `slot` using the shared engine, draining
    /// any mempool transactions that fit within the runtime's body budget.
    ///
    /// Returns the [`ProductionOutcome`] when the validator is eligible. The
    /// consumed transactions are removed from the local mempool; on failure
    /// they are restored so the next slot can retry them.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionError`] when the runtime, proposer key, or engine
    /// state reject the production attempt.
    pub fn try_produce_block(
        &self,
        slot: Slot,
        proposer: &ProposerKey,
    ) -> Result<Option<ProductionOutcome>, ProductionError<DB::Error>> {
        if self.bootstrap_pending() || !self.with_engine(Engine::local_production_enabled) {
            return Ok(None);
        }
        self.start_evidence_jobs();
        if self.block_program().is_some() && !self.with_engine(Engine::can_extend_execution) {
            return Ok(None);
        }
        self.sync_programs();
        self.revalidate_mempool();
        let candidates = self
            .mempool
            .lock()
            .expect("ChainBackend mempool poisoned")
            .execution_candidates(DEFAULT_BODY_TX_BUDGET_BYTES)
            .into_iter()
            .map(|entry| entry.bytes)
            .collect::<Vec<_>>();
        let (mut body, _) = self.select_evidence_body(&candidates);
        body.programs = self
            .program_store()
            .next_pieces(neutrin0_consensus_types::MAX_PROGRAM_PIECES_PER_BLOCK);
        // The executor lives behind an `Arc<dyn ErasedBlockExecutor>`
        // so we can hold a snapshot across the engine mutex without
        // poisoning. Production fails fast if no executor has been
        // installed; the node binary always installs one.
        self.block_executor_snapshot().map_or_else(
            || {
                Err(ProductionError::Executor(
                    "no block executor configured".to_string(),
                ))
            },
            |executor| {
                self.with_engine_mut(|e| {
                    if self.bootstrap_pending() || !e.local_production_enabled() {
                        return Ok(None);
                    }
                    if self.block_program().is_some() {
                        let height = e.head_height().checked_add(1).ok_or_else(|| {
                            ProductionError::Executor("height overflow".to_owned())
                        })?;
                        let key = e
                            .programs_for_height(height)
                            .map_err(|error| ProductionError::Executor(error.to_string()))?
                            .execution
                            .block;
                        e.authorize_consensus_body(
                            height,
                            e.head_hash(),
                            &body,
                            e.chain_spec().genesis_gas_limit,
                            &key,
                        )
                        .map_err(|err| ProductionError::Executor(err.to_string()))?;
                    }
                    let cfg = ProductionConfig { proposer };
                    crate::producer::with_witness_backoff(&body, |candidate| {
                        e.try_produce_block(slot, cfg, candidate, executor.as_ref())
                    })
                })
            },
        )
    }

    /// Apply the stale rule at the current wall-clock slot (design 08):
    /// candidates past their exclusive window without a receipt stop
    /// selecting the head, and the materialized head leaves their branch.
    pub fn refresh_stale_candidates(&self) {
        if self.bootstrap_pending() || self.is_light() {
            return;
        }
        let executor = self.replay_executor_snapshot();
        let now = crate::now_secs();
        let moved = self.with_live_engine_mut(|engine| {
            let slot = engine.clock().slot_for(now);
            engine
                .refresh_stale_candidates(slot, executor.as_deref())
                .map_err(Self::map_import_err)
        });
        match moved {
            Ok(true) => tracing::info!("materialized head left a stale candidate branch"),
            Ok(false) => {}
            Err(error) => warn!(%error, "stale candidate refresh failed"),
        }
    }
}
