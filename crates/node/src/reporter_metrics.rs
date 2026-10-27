//! Bounded reporter inventories and authenticated finalized runtime economics.

mod render;

use crate::metrics::StageMetrics;
use neutrin0_consensus_engine::store::{ReporterStorageStats, RetainedInventory};
use neutrin0_primitives::Hash;
use neutrin0_runtime_abi::operational::SettlementSnapshot;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

/// Current authenticated path inventory of the bounded proven report pool.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReportPoolMetrics {
    /// Proven reports whose opening matches the current finalized root.
    pub active: RetainedInventory,
    /// Proven reports retaining an older authenticated opening for holder refresh.
    pub dormant: RetainedInventory,
}

/// What a snapshot-bootstrapped reporter cannot currently prove from (design
/// 18): chunks it never observed and watched records whose path a peer must
/// refresh.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReporterRecovery {
    /// Chunks inside the recorded unobserved ranges.
    pub gap_chunks: u64,
    /// Watched records whose path is dormant until a holder refreshes it.
    pub dormant_paths: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct InventorySnapshot {
    available: bool,
    finalized: Hash,
    storage: ReporterStorageStats,
    pool: ReportPoolMetrics,
    recovery: ReporterRecovery,
}

#[derive(Clone, Copy, Debug)]
struct EconomicsSnapshot {
    finalized: Hash,
    height: u64,
    value: SettlementSnapshot,
    current: bool,
}

/// Reporter process events and constant-size snapshots. Labels never include
/// identities, addresses, chunk IDs or offences, so observation cannot grow the
/// Prometheus series set with chain history.
#[derive(Debug, Default)]
pub struct ReporterMetrics {
    /// Distinct new raw offences persisted by this process.
    pub detected: AtomicU64,
    /// Fresh locally proven reports persisted into the local pool.
    pub submitted: AtomicU64,
    /// Raw reports removed after a successful finalized eligibility refresh.
    pub cleaned: AtomicU64,
    /// Reports removed to free local pool capacity, excluding finality cleanup.
    pub pool_evictions: AtomicU64,
    /// Eligibility refresh attempts, including runtime execution and response checks.
    pub eligibility_queries: StageMetrics,
    /// Finalized cumulative economic query attempts.
    pub economic_queries: StageMetrics,
    /// Failed eligibility refresh attempts; failures never authorize deletion.
    pub query_failures: AtomicU64,
    /// Failed finalized economic queries, including unavailable installed runtimes.
    pub economic_query_failures: AtomicU64,
    /// Finalized height of the last successful eligibility query and applied refresh.
    pub last_success_height: AtomicU64,
    /// Whether any finalized eligibility refresh has succeeded.
    pub eligibility_available: AtomicU64,
    /// Failed durable inventory snapshots.
    pub inventory_failures: AtomicU64,
    inventory: Mutex<InventorySnapshot>,
    economics: Mutex<Option<EconomicsSnapshot>>,
}

impl ReporterMetrics {
    /// Whether unchanged durable inventory and boundary need no pool reread.
    pub(crate) fn inventory_current(&self, revision: u64, finalized: Hash) -> bool {
        let snapshot = self.inventory.lock().expect("reporter metric inventory");
        snapshot.available
            && revision != u64::MAX
            && snapshot.storage.revision == revision
            && snapshot.finalized == finalized
    }

    /// Publish a coherent inventory after a successful storage read.
    pub(crate) fn set_inventory(
        &self,
        finalized: Hash,
        storage: &ReporterStorageStats,
        pool: ReportPoolMetrics,
        recovery: ReporterRecovery,
    ) {
        *self.inventory.lock().expect("reporter metric inventory") = InventorySnapshot {
            available: true,
            finalized,
            storage: *storage,
            pool,
            recovery,
        };
    }

    /// Mark retained inventories stale while preserving the last successful values.
    pub(crate) fn inventory_unavailable(&self) {
        self.inventory
            .lock()
            .expect("reporter metric inventory")
            .available = false;
        self.inventory_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether the runtime has already supplied totals at this exact finalized boundary.
    pub(crate) fn economics_current(&self, finalized: Hash) -> bool {
        self.economics
            .lock()
            .expect("reporter economic metrics")
            .is_some_and(|snapshot| snapshot.current && snapshot.finalized == finalized)
    }

    /// Accept runtime-owned totals only after checking the queried boundary is still final.
    pub(crate) fn set_economics(&self, finalized: Hash, height: u64, value: &SettlementSnapshot) {
        *self.economics.lock().expect("reporter economic metrics") = Some(EconomicsSnapshot {
            finalized,
            height,
            value: *value,
            current: true,
        });
    }

    /// A failed or superseded query cannot present old totals as current state.
    pub(crate) fn economics_unavailable(&self) {
        if let Some(snapshot) = self
            .economics
            .lock()
            .expect("reporter economic metrics")
            .as_mut()
        {
            snapshot.current = false;
        }
    }

    /// Render fixed-label process counters, retention gauges and runtime totals.
    pub fn render(&self, out: &mut String) {
        self.render_process(out);
        self.render_inventory(out);
        self.render_economics(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_runtime_omits_amounts_and_stale_totals_remain_explicit() {
        let metrics = ReporterMetrics::default();
        let mut out = String::new();
        metrics.render(&mut out);
        assert!(out.contains("neutrin0_accountability_metrics_available 0"));
        assert!(!out.contains("neutrin0_accountability_deducted_total"));
        let mut value = SettlementSnapshot::default();
        value.totals.slash.deducted.value = u128::MAX;
        value.totals.slash.deducted.overflowed = true;
        metrics.set_economics([1; 32], 7, &value);
        metrics.economics_unavailable();
        out.clear();
        metrics.render(&mut out);
        assert!(out.contains("neutrin0_accountability_metrics_available 0"));
        assert!(out.contains("neutrin0_accountability_last_success_height 7"));
        assert!(out.contains(&format!(
            "neutrin0_accountability_deducted_total{{kind=\"slash\"}} {}",
            u128::MAX
        )));
        assert!(out.contains("effect=\"deducted\"} 1"));
        assert!(!out.contains("pubkey="));
    }
}
