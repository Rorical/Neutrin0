//! Reporter inventory metrics and the runtime's finalized settlement totals.

use neutrin0_proof_system::ProofSystem;
use neutrin0_runtime_abi::QueryRequest;
use neutrin0_runtime_abi::operational::{QUERY_METHOD_ACCOUNTABILITY_METRICS, SettlementSnapshot};
use neutrin0_storage::Database;
use std::sync::atomic::Ordering;

use super::{ChainBackend, finalized_query_state};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Refresh local inventories and runtime-owned finalized totals. The monitor
    /// calls this outside the async executor; unchanged roots and tracked identity
    /// sets never repeat WASM queries, and unchanged inventory revisions never
    /// rescan pooled proof bytes.
    pub(in crate::chain_backend) fn refresh_reporter_metrics(&self) {
        self.refresh_reporter_tracking();
        let result = self.with_engine_mut(|engine| {
            let finalized = engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?;
            let stats = engine
                .store_mut()
                .reporter_storage_stats()
                .map_err(|error| error.to_string())?;
            if !self
                .metrics
                .reporter
                .inventory_current(stats.revision, finalized.block_hash)
            {
                let [active, dormant] = engine
                    .store()
                    .evidence_pool_metrics()
                    .map_err(|error| error.to_string())?;
                let gap_chunks = engine
                    .reporter_gaps()
                    .map_err(|error| error.to_string())?
                    .iter()
                    .map(|(from, to)| to.saturating_sub(*from))
                    .fold(0_u64, u64::saturating_add);
                let dormant_paths = engine
                    .reporter_dormant_chunks()
                    .map_err(|error| error.to_string())?
                    .len() as u64;
                self.metrics.reporter.set_inventory(
                    finalized.block_hash,
                    &stats,
                    crate::reporter_metrics::ReportPoolMetrics { active, dormant },
                    crate::reporter_metrics::ReporterRecovery {
                        gap_chunks,
                        dormant_paths,
                    },
                );
            }
            Ok::<_, String>(())
        });
        if let Err(error) = result {
            self.metrics.reporter.inventory_unavailable();
            tracing::debug!(%error, "reporter inventory metrics unavailable");
        }
        if let Err(error) = self.update_finalized_economics() {
            self.metrics
                .reporter
                .economic_query_failures
                .fetch_add(1, Ordering::Relaxed);
            self.metrics.reporter.economics_unavailable();
            tracing::debug!(%error, "finalized runtime economic metrics unavailable");
        }
    }

    fn update_finalized_economics(&self) -> Result<(), String> {
        // Light clients authenticate roots but possess no execution state or
        // installed runtime. They must expose unavailable rather than genesis 0.
        if self.is_light() || self.bootstrap_pending() {
            self.metrics.reporter.economics_unavailable();
            return Ok(());
        }
        let snapshot = self.with_engine(|engine| {
            let boundary = engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(|error| error.to_string())?;
            if self.metrics.reporter.economics_current(boundary.block_hash) {
                return Ok(None);
            }
            let (state, runtime) = finalized_query_state(engine, &boundary)?;
            Ok::<_, String>(Some((boundary, state, runtime)))
        })?;
        let Some((boundary, state, runtime)) = snapshot else {
            return Ok(());
        };
        let timer = self.metrics.reporter.economic_queries.timer();
        let executor = self
            .block_executor_snapshot()
            .ok_or("installed runtime unavailable for economic metrics")?;
        let response = executor.query(
            &QueryRequest {
                method: QUERY_METHOD_ACCOUNTABILITY_METRICS.into(),
                args: Vec::new(),
            },
            runtime,
            &state,
        )?;
        if !response.is_ok() {
            return Err("installed runtime does not expose settlement metrics".into());
        }
        let value: SettlementSnapshot =
            borsh::from_slice(&response.payload).map_err(|error| error.to_string())?;
        self.with_engine(|engine| {
            if engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .ok()
                .as_ref()
                == Some(&boundary)
            {
                self.metrics
                    .reporter
                    .set_economics(boundary.block_hash, boundary.height, &value);
            } else {
                self.metrics.reporter.economics_unavailable();
            }
        });
        timer.finish(true);
        Ok(())
    }
}
