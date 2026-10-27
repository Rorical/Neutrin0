//! Latency histograms, per-stage counters and the text-format writers every
//! subsystem renders with.

#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::LATENCY_BUCKETS_SECS;

/// Cumulative latency histogram over [`LATENCY_BUCKETS_SECS`].
#[derive(Debug, Default)]
pub(crate) struct LatencyHistogram {
    sum_micros: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS_SECS.len()],
    overflow: AtomicU64,
}

impl LatencyHistogram {
    /// Record one latency and return it in whole microseconds.
    pub(crate) fn observe(&self, elapsed: Duration) -> u64 {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        let secs = elapsed.as_secs_f64();
        LATENCY_BUCKETS_SECS
            .iter()
            .position(|bound| secs <= *bound)
            .map_or(&self.overflow, |index| &self.buckets[index])
            .fetch_add(1, Ordering::Relaxed);
        micros
    }

    /// Render the `_bucket`, `_sum` and `_count` samples of `name`, with
    /// `labels` (comma-separated `key="value"` pairs) prepended to each.
    pub(crate) fn render(&self, out: &mut String, name: &str, labels: &str) {
        let separator = if labels.is_empty() { "" } else { "," };
        let mut count = 0_u64;
        for (bound, bucket) in LATENCY_BUCKETS_SECS.iter().zip(&self.buckets) {
            count += bucket.load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{separator}le=\"{bound}\"}} {count}"
            );
        }
        count += self.overflow.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{separator}le=\"+Inf\"}} {count}"
        );
        let sum = seconds(self.sum_micros.load(Ordering::Relaxed));
        if labels.is_empty() {
            let _ = writeln!(out, "{name}_sum {sum}\n{name}_count {count}");
        } else {
            let _ = writeln!(
                out,
                "{name}_sum{{{labels}}} {sum}\n{name}_count{{{labels}}} {count}"
            );
        }
    }
}

/// Counters and a latency histogram for one proving stage.
#[derive(Debug, Default)]
pub struct StageMetrics {
    ok: AtomicU64,
    failed: AtomicU64,
    latency: LatencyHistogram,
    last_micros: AtomicU64,
    max_micros: AtomicU64,
}

impl StageMetrics {
    /// Record one attempt. Latency is recorded for successes and failures
    /// alike; the outcome counters tell them apart.
    pub fn observe(&self, elapsed: Duration, ok: bool) {
        if ok {
            self.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
        let micros = self.latency.observe(elapsed);
        self.last_micros.store(micros, Ordering::Relaxed);
        self.max_micros.fetch_max(micros, Ordering::Relaxed);
    }

    /// Render this fixed-name stage in Prometheus text format.
    pub fn render(&self, out: &mut String, name: &str, help: &str) {
        let ok = self.ok.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        family(
            out,
            &format!("{name}_total"),
            &format!("{help} attempts by outcome."),
            "counter",
        );
        let _ = writeln!(out, "{name}_total{{outcome=\"ok\"}} {ok}");
        let _ = writeln!(out, "{name}_total{{outcome=\"failed\"}} {failed}");
        let histogram = format!("{name}_seconds");
        family(out, &histogram, &format!("{help} latency."), "histogram");
        self.latency.render(out, &histogram, "");
        gauge(
            out,
            &format!("{name}_last_seconds"),
            "Most recent attempt latency.",
            seconds(self.last_micros.load(Ordering::Relaxed)),
        );
        gauge(
            out,
            &format!("{name}_max_seconds"),
            "Largest observed attempt latency.",
            seconds(self.max_micros.load(Ordering::Relaxed)),
        );
    }

    /// Measure an attempt, recording failure on early return or unwinding.
    pub fn timer(&self) -> StageTimer<'_> {
        StageTimer {
            metrics: self,
            started: Instant::now(),
            ok: false,
        }
    }

    /// Time `attempt`, recording success only for `Ok` and failure on unwinding.
    pub fn time<T, E>(&self, attempt: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let timer = self.timer();
        let result = attempt();
        timer.finish(result.is_ok());
        result
    }
}

/// Records a stage attempt when dropped, including early errors and panics.
pub struct StageTimer<'a> {
    metrics: &'a StageMetrics,
    started: Instant,
    ok: bool,
}

impl StageTimer<'_> {
    /// Complete the attempt with the supplied outcome.
    pub fn finish(mut self, ok: bool) {
        self.ok = ok;
    }
}

impl Drop for StageTimer<'_> {
    fn drop(&mut self) {
        self.metrics.observe(self.started.elapsed(), self.ok);
    }
}

/// Render microseconds as decimal seconds without a lossy float cast.
pub(crate) fn seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

/// Write the `HELP` and `TYPE` lines of a metric family.
pub(crate) fn family(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// Write a metric family whose samples differ only in the `key` label.
pub(crate) fn labeled<'a, V: std::fmt::Display>(
    out: &mut String,
    name: &str,
    help: &str,
    kind: &str,
    key: &str,
    samples: impl IntoIterator<Item = (&'a str, V)>,
) {
    family(out, name, help, kind);
    for (label, value) in samples {
        let _ = writeln!(out, "{name}{{{key}=\"{label}\"}} {value}");
    }
}

/// Current values of a fixed array of counters.
pub(crate) fn loads(values: &[AtomicU64]) -> impl Iterator<Item = u64> + '_ {
    values.iter().map(|value| value.load(Ordering::Relaxed))
}

/// Write a complete unlabelled gauge.
pub(crate) fn gauge(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    family(out, name, help, "gauge");
    let _ = writeln!(out, "{name} {value}");
}

/// Write a complete unlabelled counter.
pub(crate) fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    family(out, name, help, "counter");
    let _ = writeln!(out, "{name} {value}");
}
