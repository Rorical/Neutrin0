//! Prometheus exposition of the shared sync measurements.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};

use super::{BOOTSTRAP_KINDS, FULL_CHUNK_KINDS, PHASES, RESULTS, SyncMetrics};

impl SyncMetrics {
    /// Append Prometheus exposition. FSM cursors count completed heights/chunks;
    /// full-chunk cursors are the selected provider branch's next height and
    /// chunk ID. Bootstrap pending counts resumable trie items/fragments, which
    /// can grow as authenticated nodes reveal more dependencies. Progress and
    /// full-chunk targets have explicit availability; unknown samples are omitted.
    /// The full-chunk height is a selected provider hint, while consensus target
    /// fields come from the locally authenticated next chunk boundary.
    #[allow(clippy::too_many_lines)]
    pub fn render(&self, out: &mut String) {
        family(out, "neutrin0_sync_phase", "gauge");
        let current_phase = self.phase.load(Ordering::Relaxed);
        for (index, phase) in PHASES.iter().enumerate() {
            let _ = writeln!(
                out,
                "neutrin0_sync_phase{{phase=\"{phase}\"}} {}",
                u8::from(current_phase == index)
            );
        }
        for name in [
            "neutrin0_sync_fsm_cursor",
            "neutrin0_sync_fsm_target",
            "neutrin0_sync_fsm_remaining",
        ] {
            family(out, name, "gauge");
        }
        for (unit, cursor, target) in [
            (
                "height",
                self.fsm_cursor_height.load(Ordering::Relaxed),
                self.fsm_target_height.load(Ordering::Relaxed),
            ),
            (
                "chunks",
                self.fsm_cursor_chunks.load(Ordering::Relaxed),
                self.fsm_target_chunks.load(Ordering::Relaxed),
            ),
        ] {
            for (name, value) in [
                ("neutrin0_sync_fsm_cursor", cursor),
                ("neutrin0_sync_fsm_target", target),
                ("neutrin0_sync_fsm_remaining", target.saturating_sub(cursor)),
            ] {
                let _ = writeln!(out, "{name}{{unit=\"{unit}\"}} {value}");
            }
        }
        family(out, "neutrin0_sync_inflight", "gauge");
        for (source, value) in [
            ("fsm", &self.fsm_inflight),
            ("bootstrap", &self.bootstrap_inflight),
            ("full_chunk", &self.full_chunk_inflight),
        ] {
            let _ = writeln!(
                out,
                "neutrin0_sync_inflight{{source=\"{source}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        family(out, "neutrin0_sync_stalled_reason", "gauge");
        let _ = writeln!(
            out,
            "neutrin0_sync_stalled_reason{{reason=\"history_conflict\"}} {}",
            u8::from(self.stalled_reason.load(Ordering::Relaxed) == 1)
        );
        let progress_available = self.progress_available.load(Ordering::Relaxed);
        let target_available = self.full_chunk_target_available.load(Ordering::Relaxed);
        scalar(
            out,
            "neutrin0_sync_progress_available",
            "gauge",
            progress_available,
        );
        scalar(
            out,
            "neutrin0_sync_full_chunk_target_available",
            "gauge",
            target_available,
        );
        if progress_available != 0 {
            family(out, "neutrin0_sync_fsm_progress", "gauge");
            for (kind, value) in ["head_height", "proven_height", "finalized_chunks"]
                .iter()
                .zip(&self.progress)
            {
                let _ = writeln!(
                    out,
                    "neutrin0_sync_fsm_progress{{kind=\"{kind}\"}} {}",
                    value.load(Ordering::Relaxed)
                );
            }
        }
        family(out, "neutrin0_sync_observation_failures_total", "counter");
        for (operation, value) in ["local_progress", "consensus_target"]
            .iter()
            .zip(&self.observation_failures)
        {
            let _ = writeln!(
                out,
                "neutrin0_sync_observation_failures_total{{operation=\"{operation}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        scalar(
            out,
            "neutrin0_sync_full_chunk_enabled",
            "gauge",
            self.full_chunk_enabled.load(Ordering::Relaxed),
        );
        if target_available != 0 {
            scalar(
                out,
                "neutrin0_sync_full_chunk_target_height",
                "gauge",
                self.full_chunk_target_height.load(Ordering::Relaxed),
            );
            family(out, "neutrin0_sync_full_chunk_consensus_target", "gauge");
            for (field, value) in ["chunk_id", "start_height", "end_height"]
                .iter()
                .zip(&self.full_chunk_consensus_target)
            {
                let _ = writeln!(
                    out,
                    "neutrin0_sync_full_chunk_consensus_target{{field=\"{field}\"}} {}",
                    value.load(Ordering::Relaxed)
                );
            }
        }
        family(out, "neutrin0_sync_full_chunk_cursor", "gauge");
        for (kind, value) in ["next_block", "chunk_id"]
            .iter()
            .zip(&self.full_chunk_cursors)
        {
            let _ = writeln!(
                out,
                "neutrin0_sync_full_chunk_cursor{{kind=\"{kind}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        scalar(
            out,
            "neutrin0_sync_bootstrap_pending_items",
            "gauge",
            self.bootstrap_pending_items.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrin0_sync_bootstrap_waiting",
            "gauge",
            self.bootstrap_waiting.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrin0_sync_bootstrap_target_chunks",
            "gauge",
            self.bootstrap_target_chunks.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrin0_sync_bootstrap_state_entries_accepted_total",
            "counter",
            self.bootstrap_state_entries.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrin0_sync_bootstrap_installs_total",
            "counter",
            self.bootstrap_installs.load(Ordering::Relaxed),
        );
        family(out, "neutrin0_sync_bootstrap_errors_total", "counter");
        for (outcome, value) in RESULTS.iter().zip(&self.bootstrap_errors) {
            let _ = writeln!(
                out,
                "neutrin0_sync_bootstrap_errors_total{{outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        render_results(
            out,
            "bootstrap",
            &BOOTSTRAP_KINDS,
            &self.bootstrap_requests,
            &self.bootstrap_results,
        );
        render_results(
            out,
            "full_chunk",
            &FULL_CHUNK_KINDS,
            &self.full_chunk_requests,
            &self.full_chunk_results,
        );
    }
}

fn render_results<const N: usize>(
    out: &mut String,
    name: &str,
    kinds: &[&str; N],
    requests: &[AtomicU64; N],
    results: &[[AtomicU64; RESULTS.len()]; N],
) {
    let prefix = format!("neutrin0_sync_{name}");
    family(out, &format!("{prefix}_requests_total"), "counter");
    family(out, &format!("{prefix}_results_total"), "counter");
    for (index, kind) in kinds.iter().enumerate() {
        let _ = writeln!(
            out,
            "{prefix}_requests_total{{kind=\"{kind}\"}} {}",
            requests[index].load(Ordering::Relaxed)
        );
        for (outcome, value) in RESULTS.iter().zip(&results[index]) {
            let _ = writeln!(
                out,
                "{prefix}_results_total{{kind=\"{kind}\",outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
    }
}

fn family(out: &mut String, name: &str, kind: &str) {
    let _ = writeln!(
        out,
        "# HELP {name} Sync and authenticated bootstrap measurements."
    );
    let _ = writeln!(out, "# TYPE {name} {kind}");
}
fn scalar(out: &mut String, name: &str, kind: &str, value: u64) {
    family(out, name, kind);
    let _ = writeln!(out, "{name} {value}");
}
