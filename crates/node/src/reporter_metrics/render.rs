//! Prometheus rendering of the reporter's process counters, inventory and
//! finalized economics.

use std::fmt::Write as _;
use std::sync::atomic::Ordering;

use neutrin0_runtime_abi::operational::{SettlementCounter, SettlementKindTotals};

use super::ReporterMetrics;
use crate::metrics::{counter, family, gauge};

impl ReporterMetrics {
    pub(super) fn render_process(&self, out: &mut String) {
        for (name, help, value) in [
            (
                "detected",
                "Distinct raw offences persisted by this process.",
                &self.detected,
            ),
            (
                "submitted",
                "Fresh local proven reports installed by this process.",
                &self.submitted,
            ),
            (
                "cleaned_raw_reports",
                "Raw reports cleaned after finalized runtime eligibility queries.",
                &self.cleaned,
            ),
            (
                "pool_evictions",
                "Reports evicted to free local pool capacity.",
                &self.pool_evictions,
            ),
            (
                "eligibility_query_failures",
                "Failed finalized runtime eligibility refreshes.",
                &self.query_failures,
            ),
            (
                "economic_query_failures",
                "Failed finalized runtime economic queries.",
                &self.economic_query_failures,
            ),
            (
                "inventory_failures",
                "Failed local durable inventory reads.",
                &self.inventory_failures,
            ),
        ] {
            counter(
                out,
                &format!("neutrin0_reporter_{name}_total"),
                help,
                value.load(Ordering::Relaxed),
            );
        }
        self.eligibility_queries.render(
            out,
            "neutrin0_reporter_eligibility_query",
            "Finalized eligibility query",
        );
        self.economic_queries.render(
            out,
            "neutrin0_accountability_query",
            "Finalized runtime settlement query",
        );
        gauge(
            out,
            "neutrin0_reporter_eligibility_available",
            "A finalized eligibility refresh has succeeded.",
            self.eligibility_available.load(Ordering::Relaxed),
        );
        gauge(
            out,
            "neutrin0_reporter_eligibility_last_success_height",
            "Finalized height of last applied eligibility refresh.",
            self.last_success_height.load(Ordering::Relaxed),
        );
    }

    pub(super) fn render_economics(&self, out: &mut String) {
        let snapshot = *self.economics.lock().expect("reporter economic metrics");
        gauge(
            out,
            "neutrin0_accountability_metrics_available",
            "Runtime totals are known at the current finalized boundary.",
            u8::from(snapshot.is_some_and(|value| value.current)),
        );
        if let Some(snapshot) = snapshot {
            gauge(
                out,
                "neutrin0_accountability_last_success_height",
                "Finalized height of last successful economic query.",
                snapshot.height,
            );
            for effect in EFFECTS {
                family(
                    out,
                    &format!("neutrin0_accountability_{effect}_total"),
                    &format!("Runtime-owned cumulative {effect}, amounts in wei."),
                    "counter",
                );
            }
            family(
                out,
                "neutrin0_accountability_counter_overflow",
                "Mathematical cumulative total exceeded u128; exposed value is a lower bound.",
                "gauge",
            );
            family(
                out,
                "neutrin0_accountability_pending",
                "Mandatory FIFO obligations, without estimating future transfers.",
                "gauge",
            );
            render_kind(out, "slash", &snapshot.value.totals.slash);
            render_kind(out, "inactivity", &snapshot.value.totals.inactivity);
            render_kind(out, "abandonment", &snapshot.value.totals.abandonment);
            for (kind, count) in [
                ("slash", snapshot.value.pending_slash),
                ("inactivity", snapshot.value.pending_inactivity),
                ("abandonment", snapshot.value.pending_abandonment),
            ] {
                let _ = writeln!(
                    out,
                    "neutrin0_accountability_pending{{kind=\"{kind}\"}} {count}"
                );
            }
        }
    }

    pub(super) fn render_inventory(&self, out: &mut String) {
        let snapshot = *self.inventory.lock().expect("reporter metric inventory");
        gauge(
            out,
            "neutrin0_reporter_inventory_available",
            "Local retention inventory read succeeded.",
            u8::from(snapshot.available),
        );
        for (name, help) in [
            (
                "neutrin0_reporter_retained_records",
                "Retained records by kind; signatures counts serialized BLS copies.",
            ),
            (
                "neutrin0_reporter_retained_bytes",
                "Logical retained bytes by kind; excludes database engine overhead.",
            ),
            (
                "neutrin0_evidence_pool_records",
                "Bounded proven reports by finalized opening freshness.",
            ),
            (
                "neutrin0_evidence_pool_bytes",
                "Logical proven pool bytes including serialized paths and keys.",
            ),
        ] {
            family(out, name, help, "gauge");
        }
        for (kind, inventory) in [
            ("history", snapshot.storage.history),
            ("sources", snapshot.storage.sources),
            ("headers", snapshot.storage.headers),
            ("boundaries", snapshot.storage.boundaries),
            ("identities", snapshot.storage.validators),
            ("indexes", snapshot.storage.index),
            ("signed_artifacts", snapshot.storage.signed_artifacts),
            ("proof_dependencies", snapshot.storage.proof_dependencies),
            ("contexts", snapshot.storage.contexts),
            ("subtrees", snapshot.storage.subtrees),
            ("signatures", snapshot.storage.signatures),
            ("raw_reports", snapshot.storage.raw_reports),
        ] {
            let _ = writeln!(
                out,
                "neutrin0_reporter_retained_records{{kind=\"{kind}\"}} {}",
                inventory.records
            );
            let _ = writeln!(
                out,
                "neutrin0_reporter_retained_bytes{{kind=\"{kind}\"}} {}",
                inventory.bytes
            );
        }
        for (state, inventory) in [
            ("active", snapshot.pool.active),
            ("dormant", snapshot.pool.dormant),
        ] {
            let _ = writeln!(
                out,
                "neutrin0_evidence_pool_records{{state=\"{state}\"}} {}",
                inventory.records
            );
            let _ = writeln!(
                out,
                "neutrin0_evidence_pool_bytes{{state=\"{state}\"}} {}",
                inventory.bytes
            );
        }
        for (name, help, value) in [
            (
                "neutrin0_reporter_gap_chunks",
                "Chunks a snapshot bootstrap skipped, whose signatures this reporter never observed.",
                snapshot.recovery.gap_chunks,
            ),
            (
                "neutrin0_reporter_dormant_paths",
                "Watched records whose History path awaits refresh from a peer or archive.",
                snapshot.recovery.dormant_paths,
            ),
        ] {
            gauge(out, name, help, value);
        }
        for (name, value) in [
            ("cleaned_records", snapshot.storage.cleaned_records),
            ("cleaned_bytes", snapshot.storage.cleaned_bytes),
            ("proven_pool_removals", snapshot.storage.report_removals),
            ("raw_pool_removals", snapshot.storage.raw_report_removals),
        ] {
            counter(
                out,
                &format!("neutrin0_reporter_{name}_total"),
                "Durable local retention deletions.",
                value,
            );
        }
    }
}

/// Settlement effects in the field order of [`SettlementKindTotals`].
const EFFECTS: [&str; 6] = [
    "admitted",
    "executed",
    "zero_deductions",
    "deducted",
    "rewarded",
    "burned",
];

fn render_kind(out: &mut String, kind: &str, totals: &SettlementKindTotals) {
    let values = [
        totals.admitted,
        totals.executed,
        totals.zero_deductions,
        totals.deducted,
        totals.rewarded,
        totals.burned,
    ];
    for (effect, value) in EFFECTS.into_iter().zip(values) {
        render_total(out, effect, kind, value);
    }
}

fn render_total(out: &mut String, effect: &str, kind: &str, value: SettlementCounter) {
    let _ = writeln!(
        out,
        "neutrin0_accountability_{effect}_total{{kind=\"{kind}\"}} {}",
        value.value
    );
    let _ = writeln!(
        out,
        "neutrin0_accountability_counter_overflow{{kind=\"{kind}\",effect=\"{effect}\"}} {}",
        u8::from(value.overflowed)
    );
}
