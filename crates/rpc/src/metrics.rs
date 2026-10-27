//! Bounded JSON-RPC transport observations; method names are classified before labeling.
use std::fmt::Write as _;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;
const KINDS: [&str; 12] = [
    "system",
    "chain",
    "state",
    "mempool",
    "runtime",
    "history",
    "programs",
    "proving",
    "ethereum",
    "unknown",
    "batch",
    "notification",
];
/// Method families are the `KINDS` entries before this index.
const UNKNOWN: usize = 9;
pub(crate) const BATCH: usize = 10;
pub(crate) const NOTIFICATION: usize = 11;
const OUTCOMES: [&str; 6] = [
    "ok",
    "failed",
    "rate_limited",
    "busy",
    "timeout",
    "cancelled",
];
const CANCELLED: usize = 5;
const BOUNDS: [f64; 8] = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 2.0, 10.0];
#[derive(Debug, Default)]
struct Stage {
    outcomes: [AtomicU64; OUTCOMES.len()],
    inflight: AtomicU64,
    /// The final slot counts latencies above every bound.
    buckets: [AtomicU64; BOUNDS.len() + 1],
    micros: AtomicU64,
}
/// Process-local RPC counters shared by every connection.
#[derive(Debug, Default)]
pub struct RpcMetrics {
    stages: [Stage; KINDS.len()],
}
impl RpcMetrics {
    pub(crate) fn kind(method: &str) -> usize {
        method.split_once('_').map_or(UNKNOWN, |(prefix, _)| {
            // The Ethereum-compatible surface shares one family.
            let family = match prefix {
                "eth" | "net" | "web3" => "ethereum",
                other => other,
            };
            KINDS[..UNKNOWN]
                .iter()
                .position(|kind| *kind == family)
                .unwrap_or(UNKNOWN)
        })
    }
    pub(crate) fn begin(self: &Arc<Self>, kind: usize) -> RpcObservation {
        self.stages[kind].inflight.fetch_add(1, Ordering::Relaxed);
        RpcObservation {
            metrics: Arc::clone(self),
            kind,
            started: Instant::now(),
            outcome: CANCELLED,
        }
    }
    /// Export only fixed method-family and outcome labels.
    pub fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# HELP neutrin0_rpc_requests_total JSON-RPC requests or batches by method family and outcome.\n# TYPE neutrin0_rpc_requests_total counter\n# HELP neutrin0_rpc_inflight JSON-RPC requests or batches currently in flight.\n# TYPE neutrin0_rpc_inflight gauge\n# HELP neutrin0_rpc_seconds JSON-RPC request or batch latency including admission rejection.\n# TYPE neutrin0_rpc_seconds histogram"
        );
        for (kind, stage) in KINDS.iter().zip(&self.stages) {
            for (outcome, count) in OUTCOMES.iter().zip(&stage.outcomes) {
                let _ = writeln!(
                    out,
                    "neutrin0_rpc_requests_total{{family=\"{kind}\",outcome=\"{outcome}\"}} {}",
                    count.load(Ordering::Relaxed)
                );
            }
            let _ = writeln!(
                out,
                "neutrin0_rpc_inflight{{family=\"{kind}\"}} {}",
                stage.inflight.load(Ordering::Relaxed)
            );
            let mut cumulative = 0;
            for (bound, count) in BOUNDS.iter().zip(&stage.buckets) {
                cumulative += count.load(Ordering::Relaxed);
                let _ = writeln!(
                    out,
                    "neutrin0_rpc_seconds_bucket{{family=\"{kind}\",le=\"{bound}\"}} {cumulative}"
                );
            }
            cumulative += stage.buckets[BOUNDS.len()].load(Ordering::Relaxed);
            let micros = stage.micros.load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "neutrin0_rpc_seconds_bucket{{family=\"{kind}\",le=\"+Inf\"}} {cumulative}\nneutrin0_rpc_seconds_count{{family=\"{kind}\"}} {cumulative}\nneutrin0_rpc_seconds_sum{{family=\"{kind}\"}} {}.{:06}",
                micros / 1_000_000,
                micros % 1_000_000
            );
        }
    }
}
pub(crate) struct RpcObservation {
    metrics: Arc<RpcMetrics>,
    kind: usize,
    started: Instant,
    outcome: usize,
}
impl RpcObservation {
    /// Classify by JSON-RPC error code. Only the `runtime_call` deadline is a
    /// timeout; runtime execution failures count as `failed`.
    pub(crate) fn finish(mut self, code: Option<i32>) {
        use crate::server::errors::{BUSY_CODE, RATE_LIMITED_CODE, RUNTIME_TIMEOUT_CODE};
        self.outcome = match code {
            None => 0,
            Some(RATE_LIMITED_CODE) => 2,
            Some(BUSY_CODE) => 3,
            Some(RUNTIME_TIMEOUT_CODE) => 4,
            Some(_) => 1,
        };
    }
}
impl Drop for RpcObservation {
    fn drop(&mut self) {
        let stage = &self.metrics.stages[self.kind];
        stage.inflight.fetch_sub(1, Ordering::Relaxed);
        stage.outcomes[self.outcome].fetch_add(1, Ordering::Relaxed);
        let elapsed = self.started.elapsed();
        stage.micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let bucket = BOUNDS
            .iter()
            .position(|bound| elapsed.as_secs_f64() <= *bound)
            .unwrap_or(BOUNDS.len());
        stage.buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_and_error_classes_are_bounded() {
        let metrics = Arc::new(RpcMetrics::default());
        drop(metrics.begin(UNKNOWN));
        metrics.begin(4).finish(Some(-32012));
        metrics.begin(4).finish(Some(-32014));
        metrics.begin(0).finish(None);
        assert_eq!(RpcMetrics::kind("user_123random"), UNKNOWN);
        assert_eq!(KINDS[RpcMetrics::kind("eth_call")], "ethereum");
        assert_eq!(KINDS[RpcMetrics::kind("web3_clientVersion")], "ethereum");
        let mut out = String::new();
        metrics.render(&mut out);
        assert!(out.contains("family=\"unknown\",outcome=\"cancelled\"} 1"));
        assert!(out.contains("family=\"runtime\",outcome=\"timeout\"} 1"));
        assert!(out.contains("family=\"runtime\",outcome=\"failed\"} 1"));
        assert!(out.contains("neutrin0_rpc_inflight{family=\"unknown\"} 0"));
    }
}
