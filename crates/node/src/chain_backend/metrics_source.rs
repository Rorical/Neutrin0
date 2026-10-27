//! Scrape adapter: samples engine, sync and mempool state for the metrics endpoint.

use super::ChainBackend;
use crate::metrics::{
    BftSessionGauge, MetricsSnapshot, MetricsSource, NodeMetrics, counter, family, gauge, seconds,
};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

impl<DB, P> MetricsSource for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    fn metrics(&self) -> &NodeMetrics {
        &self.metrics
    }

    fn render_subsystems(&self, out: &mut String) {
        self.rpc_metrics.render(out);
        if let Some(tasks) = self
            .background_tasks
            .lock()
            .expect("background tasks mutex")
            .as_ref()
        {
            tasks.render_metrics(out);
        }
        if let Some(network) = self
            .network_metrics
            .lock()
            .expect("network metrics")
            .as_ref()
        {
            network.render(out);
        }
        if let Some(sync) = self.sync_status() {
            sync.render_metrics(out);
        }
        self.process_metrics
            .lock()
            .expect("process metrics")
            .sample(out);
        counter(
            out,
            "neutrin0_history_prune_failures_total",
            "Finality advances whose history and state pruning failed; disk grows while they continue.",
            self.history.prune_failures(),
        );
        render_storage(
            out,
            self.with_engine(|engine| engine.store().db().statistics()),
        );
    }

    fn snapshot(&self) -> MetricsSnapshot {
        // Retention retries ride on the health tick; only the gauges it
        // publishes are rendered at scrape time.
        self.refresh_reporter_metrics();
        let (peers, syncing, sync_awaiting_peer) =
            self.sync_status().map_or((0, true, false), |status| {
                (
                    status.peer_count(),
                    status.is_syncing(),
                    status.awaiting_first_peer(),
                )
            });
        let mempool = u64::try_from(self.mempool_len()).unwrap_or(u64::MAX);
        let bootstrap_pending = self.bootstrap_pending();
        let storage_pressure = self.storage_pressure();
        let upgrade_missing = self.scheduled_missing_programs();
        let (checkpoint, trust_anchor_expired, history_conflict) =
            self.light_health().map_or((None, false, false), |health| {
                (Some(health.checkpoint), health.expired, health.halted)
            });
        self.with_engine(|engine| {
            MetricsSnapshot {
                doppelganger: engine.doppelganger().is_some(),
                head_height: checkpoint.map_or_else(|| engine.head_height(), |c| c.boundary.height),
                certified_execution_height: engine
                    .certified_execution_boundary()
                    .map_or(0, |b| b.height),
                execution_ahead_blocks: if checkpoint.is_none() {
                    engine.head_height().saturating_sub(
                        engine
                            .finalized_next_chunk_id()
                            .saturating_mul(engine.chain_spec().consensus.chunk_size),
                    )
                } else {
                    0
                },
                execution_certification_age_seconds: engine
                    .execution_certified_at_secs()
                    .map_or(0, |at| crate::now_secs().saturating_sub(at)),
                execution_backpressure: checkpoint.is_none() && !engine.can_extend_execution(),
                finalized_chunks: checkpoint.map_or_else(
                    || engine.finalized_next_chunk_id(),
                    |c| c.boundary.next_chunk_id,
                ),
                pruned_before_chunk: engine
                    .retention_info()
                    .map_or(0, |info| info.pruned_before_chunk),
                // A proof-only checkpoint commits to the validator root, not a
                // validator list. Do not expose the unrelated genesis engine set.
                validator_set_available: checkpoint.is_none() && !bootstrap_pending,
                active_validators: checkpoint.map_or_else(
                    || {
                        u64::try_from(
                            engine
                                .active_validator_set()
                                .iter()
                                .filter(|validator| validator.effective_stake > 0)
                                .count(),
                        )
                        .unwrap_or(u64::MAX)
                    },
                    |_| 0,
                ),
                validator_seats: checkpoint.map_or_else(
                    || u64::try_from(engine.active_validator_set().len()).unwrap_or(u64::MAX),
                    |_| 0,
                ),
                peers,
                syncing,
                sync_awaiting_peer,
                bootstrap_pending,
                trust_anchor_expired,
                history_conflict,
                storage_pressure,
                upgrade_scheduled: upgrade_missing.is_some(),
                upgrade_missing_programs: upgrade_missing.map_or(0, |missing| {
                    u64::try_from(missing.len()).unwrap_or(u64::MAX)
                }),
                mempool,
                bft_sessions: engine
                    .bft_session_overview()
                    .into_iter()
                    .map(|session| BftSessionGauge {
                        total_stake: session.stake[0],
                        prevote_stake: session.stake[1],
                        precommit_stake: session.stake[2],
                        nil_prevote_stake: session.stake[3],
                        nil_precommit_stake: session.stake[4],
                        chunk_id: session.chunk_id,
                        round: session.round,
                        local_prevoted: session.local_prevoted,
                        local_precommitted: session.local_precommitted,
                        prevote_quorum: session.prevote_quorum,
                        precommit_quorum: session.precommit_quorum,
                    })
                    .collect(),
            }
        })
    }
}

fn render_storage(out: &mut String, stats: Option<neutrin0_storage::DatabaseStatistics>) {
    use std::fmt::Write as _;
    gauge(
        out,
        "neutrin0_storage_metrics_available",
        "Persistent backend statistics available.",
        u8::from(stats.is_some()),
    );
    let Some(stats) = stats else {
        return;
    };
    for name in [
        "neutrin0_storage_operations_total",
        "neutrin0_storage_errors_total",
    ] {
        family(
            out,
            name,
            "Database operations since backend open.",
            "counter",
        );
    }
    family(
        out,
        "neutrin0_storage_operation_seconds",
        "Database operation wall time.",
        "summary",
    );
    for (index, operation) in neutrin0_storage::DATABASE_OPERATIONS
        .into_iter()
        .enumerate()
    {
        let attempts = stats.attempts[index];
        let _ = writeln!(
            out,
            "neutrin0_storage_operations_total{{operation=\"{operation}\"}} {attempts}\n\
             neutrin0_storage_errors_total{{operation=\"{operation}\"}} {}\n\
             neutrin0_storage_operation_seconds_sum{{operation=\"{operation}\"}} {}\n\
             neutrin0_storage_operation_seconds_count{{operation=\"{operation}\"}} {attempts}",
            stats.failures[index],
            seconds(stats.micros[index]),
        );
    }
    for (name, value) in [
        ("neutrin0_storage_sst_bytes", stats.sst_bytes),
        ("neutrin0_storage_memtable_bytes", stats.memtable_bytes),
        (
            "neutrin0_storage_pending_compaction_bytes",
            stats.pending_compaction_bytes,
        ),
    ] {
        if let Some(value) = value {
            gauge(
                out,
                name,
                "Aggregated RocksDB property across column families.",
                value,
            );
        }
    }
}
