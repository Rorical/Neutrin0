//! The node-level exposition: chain, worker and BFT session gauges followed
//! by every subsystem's families.

use std::fmt::Write as _;
use std::sync::atomic::Ordering;

use super::{MetricsSnapshot, NodeMetrics, counter, family, gauge};

/// Render the Prometheus text exposition for `metrics` and `snapshot`.
#[must_use]
pub fn render(metrics: &NodeMetrics, snapshot: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(4096);
    render_chain_gauges(&mut out, snapshot);
    render_worker_gauges(&mut out, metrics);
    render_sessions(&mut out, snapshot);
    metrics.proof_pipeline.render(&mut out);
    metrics.reporter.render(&mut out);
    metrics.execution.render(&mut out);
    metrics
        .block_proofs
        .render(&mut out, "neutrin0_block_proof", "Block proof");
    metrics
        .chunk_proofs
        .render(&mut out, "neutrin0_chunk_proof", "Complete chunk proof");
    out
}

fn render_chain_gauges(out: &mut String, snapshot: &MetricsSnapshot) {
    render_validator_gauges(out, snapshot);
    gauge(
        out,
        "neutrin0_head_height",
        "Unfinalised head height.",
        snapshot.head_height,
    );
    gauge(
        out,
        "neutrin0_certified_execution_height",
        "Pending execution certificate boundary height; 0 when absent.",
        snapshot.certified_execution_height,
    );
    gauge(
        out,
        "neutrin0_execution_ahead_blocks",
        "Executed blocks above complete-proof finality.",
        snapshot.execution_ahead_blocks,
    );
    gauge(
        out,
        "neutrin0_execution_certification_age_seconds",
        "Age in seconds of the pending durable execution certificate; 0 when absent.",
        snapshot.execution_certification_age_seconds,
    );
    gauge(
        out,
        "neutrin0_execution_backpressure",
        "Ordinary production has filled its authenticated execution window (0 or 1).",
        u64::from(snapshot.execution_backpressure),
    );
    gauge(
        out,
        "neutrin0_finalized_chunks",
        "Number of chunks finalized by complete chunk proofs.",
        snapshot.finalized_chunks,
    );
    gauge(
        out,
        "neutrin0_storage_pressure",
        "Data filesystem below its free-space quota; production and new candidates paused (0 or 1).",
        u8::from(snapshot.storage_pressure),
    );
    gauge(
        out,
        "neutrin0_doppelganger_detected",
        "Another process signed with the local validator key; signing and production paused (0 or 1).",
        u8::from(snapshot.doppelganger),
    );
    gauge(
        out,
        "neutrin0_upgrade_scheduled",
        "Governance enacted a program switch that has not activated (0 or 1).",
        u8::from(snapshot.upgrade_scheduled),
    );
    gauge(
        out,
        "neutrin0_upgrade_missing_programs",
        "Programs of the scheduled switch not installed locally; 0 when none is scheduled.",
        snapshot.upgrade_missing_programs,
    );
    gauge(
        out,
        "neutrin0_pruned_before_chunk",
        "Chunks below this count may have had raw data pruned.",
        snapshot.pruned_before_chunk,
    );
    gauge(
        out,
        "neutrin0_peers",
        "Connected libp2p peers.",
        snapshot.peers,
    );
    gauge(
        out,
        "neutrin0_syncing",
        "1 while the sync driver has not reached the live-following state.",
        u8::from(snapshot.syncing),
    );
    gauge(
        out,
        "neutrin0_mempool_transactions",
        "Buffered mempool transactions.",
        snapshot.mempool,
    );
}

fn render_validator_gauges(out: &mut String, snapshot: &MetricsSnapshot) {
    gauge(
        out,
        "neutrin0_validator_set_available",
        "An authenticated current validator list is locally available.",
        u8::from(snapshot.validator_set_available),
    );
    if snapshot.validator_set_available {
        gauge(
            out,
            "neutrin0_validator_seats",
            "Consensus seats including zero-weight identities.",
            snapshot.validator_seats,
        );
        gauge(
            out,
            "neutrin0_active_validators",
            "Unslashed consensus validators with positive effective stake.",
            snapshot.active_validators,
        );
    }
}

fn render_worker_gauges(out: &mut String, metrics: &NodeMetrics) {
    counter(
        out,
        "neutrin0_blocks_produced_total",
        "Blocks produced by the local proposer.",
        metrics.blocks_produced.load(Ordering::Relaxed),
    );
    gauge(
        out,
        "neutrin0_block_proof_queue_pending",
        "Block proof jobs waiting for a worker.",
        metrics.block_proof_queue_pending.load(Ordering::Relaxed),
    );
    gauge(
        out,
        "neutrin0_block_proof_queue_running",
        "Block proof jobs currently proving.",
        metrics
            .proof_pipeline
            .budget
            .inflight(crate::proof_metrics::ProofStage::Block),
    );
    let coverage = metrics.proof_pipeline.fact_coverage();
    gauge(
        out,
        "neutrin0_last_chunk_fact_coverage_available",
        "A locally proven successful chunk has supplied coherent fact coverage.",
        u8::from(coverage.is_some()),
    );
    if let Some((covered, total)) = coverage {
        gauge(
            out,
            "neutrin0_last_chunk_fact_checks_covered",
            "Unique fact checks answered by attached receipts in the latest successfully locally proven chunk.",
            covered,
        );
        gauge(
            out,
            "neutrin0_last_chunk_fact_checks",
            "Unique fact checks requested by the latest successfully locally proven chunk.",
            total,
        );
    }
    gauge(
        out,
        "neutrin0_block_proof_queue_launched",
        "Dispatched block workers including those awaiting global proof capacity.",
        metrics.block_proof_queue_launched.load(Ordering::Relaxed),
    );
}

/// BFT sessions exposed as labelled slots; the rest are only counted.
const SESSION_SLOTS: usize = 64;

fn render_sessions(out: &mut String, snapshot: &MetricsSnapshot) {
    // Labels describe bounded positions, while chunk identities are values.
    for (name, help) in [
        ("neutrin0_bft_session", "Current BFT session phase flags."),
        ("neutrin0_bft_session_round", "Current BFT session round."),
        (
            "neutrin0_bft_session_chunk",
            "Chunk identity as a value, never a label.",
        ),
        (
            "neutrin0_bft_session_stake",
            "Eligible stake by phase in the current round, in wei.",
        ),
    ] {
        family(out, name, help, "gauge");
    }
    for (slot, session) in snapshot.bft_sessions.iter().take(SESSION_SLOTS).enumerate() {
        let _ = writeln!(
            out,
            "neutrin0_bft_session_round{{slot=\"{slot}\"}} {}",
            session.round
        );
        let _ = writeln!(
            out,
            "neutrin0_bft_session_chunk{{slot=\"{slot}\"}} {}",
            session.chunk_id
        );
        for (phase, stake) in [
            ("total", session.total_stake),
            ("prevote", session.prevote_stake),
            ("precommit", session.precommit_stake),
            ("nil_prevote", session.nil_prevote_stake),
            ("nil_precommit", session.nil_precommit_stake),
        ] {
            let _ = writeln!(
                out,
                "neutrin0_bft_session_stake{{slot=\"{slot}\",phase=\"{phase}\"}} {stake}"
            );
        }
        for (flag, value) in [
            ("local_prevoted", session.local_prevoted),
            ("local_precommitted", session.local_precommitted),
            ("prevote_quorum", session.prevote_quorum),
            ("precommit_quorum", session.precommit_quorum),
        ] {
            let _ = writeln!(
                out,
                "neutrin0_bft_session{{slot=\"{slot}\",flag=\"{flag}\"}} {}",
                u8::from(value)
            );
        }
    }
    gauge(
        out,
        "neutrin0_bft_sessions",
        "Number of live BFT sessions.",
        snapshot.bft_sessions.len(),
    );
    gauge(
        out,
        "neutrin0_bft_sessions_unexposed",
        "Sessions beyond the fixed 64-slot exposition budget.",
        snapshot.bft_sessions.len().saturating_sub(SESSION_SLOTS),
    );
}
