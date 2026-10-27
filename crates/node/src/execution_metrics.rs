//! Fixed-cardinality execution, admission, import and consensus observations.

mod metered;

pub(crate) use metered::MeteredExecutor;

use crate::metrics::{StageMetrics, counter, labeled, loads};
use neutrin0_consensus_engine::BftAction;
use neutrin0_primitives::Hash;
use std::collections::BTreeMap;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Runtime `TxValidity` codes by wire value, then a trap slot.
const VALIDITY_CODES: [&str; 9] = [
    "valid",
    "malformed",
    "bad_signature",
    "nonce_mismatch",
    "insufficient_balance",
    "unauthorized",
    "unknown_type",
    "state_read_failed",
    "runtime_trap",
];
const RUNTIME_TRAP: usize = VALIDITY_CODES.len() - 1;
const ADMISSIONS: [&str; 5] = [
    "accepted",
    "duplicate",
    "capacity",
    "too_large",
    "runtime_rejected",
];
const ACTIONS: [&str; 9] = [
    "prevote",
    "precommit",
    "aggregate_prevote",
    "aggregate_precommit",
    "quorum",
    "proposal",
    "nil_vote",
    "round_change",
    "round_change_certificate",
];

/// Process-local observations; executed gas and transactions include replay attempts.
#[derive(Debug, Default)]
pub struct ExecutionMetrics {
    /// Ordinary WASM execution attempts, including dry runs and replays.
    pub blocks: StageMetrics,
    /// Runtime transaction validation attempts.
    pub validation: StageMetrics,
    /// Runtime read-only query attempts.
    pub queries: StageMetrics,
    /// Block imports including header verification and ordinary execution.
    pub block_imports: StageMetrics,
    /// Incoming block receipt verification and import.
    pub block_verification: StageMetrics,
    /// Incoming complete chunk receipt verification and import.
    pub chunk_verification: StageMetrics,
    /// Incoming recursive history receipt verification and import.
    pub history_verification: StageMetrics,
    /// Time from the first locally opened BFT session to its finalization.
    pub finalization: StageMetrics,
    /// Time from the first locally opened BFT session to its complete certificate.
    pub certificate: StageMetrics,
    /// Time from the start of the chunk's last slot to the local BFT session
    /// opening, which needs every block proof of the chunk.
    pub tail_ready: StageMetrics,
    /// Time from the start of the chunk's last slot to its complete certificate.
    pub certificate_lag: StageMetrics,
    /// Certificate time past the end of the chunk's last slot: `ok` when the
    /// certificate preceded the slot end, `failed` when the next chunk's first
    /// production slot had to wait.
    pub certificate_stall: StageMetrics,
    /// Time from the start of the chunk's last slot to durable finality.
    pub finality_lag: StageMetrics,
    /// Gas returned by successful ordinary execution attempts, including replay.
    pub gas: AtomicU64,
    /// Transactions in successfully executed bodies, including replay.
    pub transactions: AtomicU64,
    /// Unique newly finalized chunks observed since startup, excluding bootstrap prefixes.
    pub finalized_chunks: AtomicU64,
    /// Transactions in newly observed finalized chunks, excluding bootstrap prefixes.
    pub finalized_transactions: AtomicU64,
    /// Actual header gas in newly observed finalized chunks.
    pub finalized_gas: AtomicU64,
    /// Finalized chunks whose retained bodies could not be counted.
    pub finalized_observation_failures: AtomicU64,
    /// Highest finalized chunk accounted by this process.
    pub(crate) observed_finalized: Mutex<Option<u64>>,
    validity_codes: [AtomicU64; VALIDITY_CODES.len()],
    admissions: [AtomicU64; ADMISSIONS.len()],
    actions: [AtomicU64; ACTIONS.len()],
    timeout_actions: AtomicU64,
    opened: Mutex<BTreeMap<u64, SessionTiming>>,
}

/// Local timing of one BFT session relative to the slot of its chunk's last block.
#[derive(Debug, Clone, Copy)]
struct SessionTiming {
    opened: Instant,
    /// Wall-clock start and end of the chunk's last slot when the header is known.
    tail_slot: Option<(SystemTime, SystemTime)>,
    certified: bool,
}

/// Components of a certificate's lag behind its chunk's last slot.
#[derive(Debug, Clone, Copy)]
pub struct CertificateLag {
    /// Time from the local session opening to the certificate.
    pub bft: Duration,
    /// Time from the last slot's start to the certificate, when the slot is known.
    pub since_slot_start: Option<Duration>,
    /// Certificate time past the last slot's end; zero when it arrived in time.
    pub stall: Option<Duration>,
}

fn unix(secs: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// Wall-clock time elapsed since `at`, zero when `at` is in the future.
fn since(at: SystemTime) -> Duration {
    SystemTime::now().duration_since(at).unwrap_or_default()
}
impl ExecutionMetrics {
    /// Record admission result using a fixed error classification.
    pub fn admission(&self, result: &Result<Hash, neutrin0_mempool::InsertError>) {
        let index = match result {
            Ok(_) => 0,
            Err(neutrin0_mempool::InsertError::Duplicate) => 1,
            Err(neutrin0_mempool::InsertError::CapacityExceeded) => 2,
            Err(neutrin0_mempool::InsertError::TooLarge) => 3,
            Err(
                neutrin0_mempool::InsertError::RejectedByValidator
                | neutrin0_mempool::InsertError::ReplacementUnderpriced
                | neutrin0_mempool::InsertError::ZeroFee
                | neutrin0_mempool::InsertError::AccountLimit,
            ) => 4,
        };
        self.admissions[index].fetch_add(1, Ordering::Relaxed);
    }
    /// Count a generated BFT action. Re-publication is intentionally counted.
    pub fn action(&self, action: &BftAction) {
        let index = match action {
            BftAction::BroadcastPrevote(_) => 0,
            BftAction::BroadcastPrecommit(_) => 1,
            BftAction::PublishAggregatePrevote { .. } => 2,
            BftAction::PublishAggregatePrecommit { .. } => 3,
            BftAction::QuorumReached(_) => 4,
            BftAction::BroadcastProposal(_) => 5,
            BftAction::BroadcastNilVote(_) => 6,
            BftAction::BroadcastRoundChange(_) => 7,
            BftAction::BroadcastRoundChangeCertificate(_) => 8,
        };
        self.actions[index].fetch_add(1, Ordering::Relaxed);
    }
    /// Count actions generated by a phase-deadline tick, including retransmission.
    pub fn timeout_actions(&self, count: usize) {
        self.timeout_actions
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
    /// Track a first local session opening with a fixed 64-entry bound.
    /// `tail_slot` is the unix-second start and end of the chunk's last slot.
    pub fn opened(&self, chunk: u64, tail_slot: Option<(u64, u64)>) {
        let mut entries = self.opened.lock().expect("BFT metrics timings");
        if entries.contains_key(&chunk) {
            return;
        }
        if entries.len() >= 64 {
            entries.pop_first();
        }
        let tail_slot = tail_slot.and_then(|(start, end)| Some((unix(start)?, unix(end)?)));
        if let Some((start, _)) = tail_slot {
            self.tail_ready.observe(since(start), true);
        }
        entries.insert(
            chunk,
            SessionTiming {
                opened: Instant::now(),
                tail_slot,
                certified: false,
            },
        );
    }
    /// Record the first complete certificate of a locally opened session and
    /// return its lag components; later notifications for the chunk are ignored.
    pub fn certified(&self, chunk: u64) -> Option<CertificateLag> {
        let mut entries = self.opened.lock().expect("BFT metrics timings");
        let timing = entries.get_mut(&chunk)?;
        if timing.certified {
            return None;
        }
        timing.certified = true;
        let (opened, tail_slot) = (timing.opened, timing.tail_slot);
        drop(entries);
        let bft = opened.elapsed();
        self.certificate.observe(bft, true);
        let (since_slot_start, stall) = tail_slot.map_or((None, None), |(start, end)| {
            let lag = since(start);
            let stall = since(end);
            self.certificate_lag.observe(lag, true);
            self.certificate_stall.observe(stall, stall.is_zero());
            (Some(lag), Some(stall))
        });
        Some(CertificateLag {
            bft,
            since_slot_start,
            stall,
        })
    }
    /// Record finality only after successful durable engine admission.
    pub fn finalized(&self, chunk: u64) {
        let mut entries = self.opened.lock().expect("BFT metrics timings");
        if let Some(timing) = entries.remove(&chunk) {
            self.finalization.observe(timing.opened.elapsed(), true);
            if let Some((start, _)) = timing.tail_slot {
                self.finality_lag.observe(since(start), true);
            }
        }
        entries.retain(|id, _| *id > chunk);
    }
    /// Render fixed-name, fixed-label observations.
    pub fn render(&self, out: &mut String) {
        self.render_stages(out);
        for (name, help, value) in [
            (
                "neutrin0_execution_gas_total",
                "Gas from successful execution attempts including replay",
                self.gas.load(Ordering::Relaxed),
            ),
            (
                "neutrin0_execution_transactions_total",
                "Transactions in successful execution attempts including replay",
                self.transactions.load(Ordering::Relaxed),
            ),
            (
                "neutrin0_bft_deadline_actions_total",
                "Actions produced by deadline ticks including retransmission",
                self.timeout_actions.load(Ordering::Relaxed),
            ),
        ] {
            counter(out, name, help, value);
        }
        for (name, value) in [
            (
                "neutrin0_finalized_observed_chunks_total",
                &self.finalized_chunks,
            ),
            (
                "neutrin0_finalized_observed_transactions_total",
                &self.finalized_transactions,
            ),
            ("neutrin0_finalized_observed_gas_total", &self.finalized_gas),
            (
                "neutrin0_finalized_observation_failures_total",
                &self.finalized_observation_failures,
            ),
        ] {
            counter(
                out,
                name,
                "Newly observed finalized execution since startup excluding bootstrap prefixes.",
                value.load(Ordering::Relaxed),
            );
        }
        self.render_outcomes(out);
    }
    fn render_outcomes(&self, out: &mut String) {
        labeled(
            out,
            "neutrin0_transaction_validity_total",
            "Runtime validation verdicts including traps.",
            "counter",
            "code",
            VALIDITY_CODES.into_iter().zip(loads(&self.validity_codes)),
        );
        labeled(
            out,
            "neutrin0_transaction_admissions_total",
            "Mempool admission attempts.",
            "counter",
            "outcome",
            ADMISSIONS.into_iter().zip(loads(&self.admissions)),
        );
        labeled(
            out,
            "neutrin0_bft_actions_total",
            "Generated BFT actions including retransmission.",
            "counter",
            "action",
            ACTIONS.into_iter().zip(loads(&self.actions)),
        );
    }
    fn render_stages(&self, out: &mut String) {
        for (stage, name, help) in [
            (
                &self.blocks,
                "neutrin0_execution",
                "Ordinary execution including replay",
            ),
            (
                &self.validation,
                "neutrin0_transaction_validation",
                "Runtime transaction validation",
            ),
            (
                &self.queries,
                "neutrin0_runtime_query",
                "Read-only runtime query",
            ),
            (
                &self.block_imports,
                "neutrin0_block_import",
                "Block or batch validation and import",
            ),
            (
                &self.block_verification,
                "neutrin0_block_receipt_import",
                "Block receipt batch verification and import",
            ),
            (
                &self.chunk_verification,
                "neutrin0_chunk_receipt_import",
                "Chunk receipt verification and import",
            ),
            (
                &self.history_verification,
                "neutrin0_history_receipt_import",
                "History receipt verification and import",
            ),
            (
                &self.finalization,
                "neutrin0_bft_finalization",
                "Finalization since first local session opening",
            ),
            (
                &self.certificate,
                "neutrin0_bft_certificate",
                "Complete certificate since first local session opening",
            ),
            (
                &self.tail_ready,
                "neutrin0_chunk_tail_ready",
                "Local BFT session opening since the chunk's last slot start",
            ),
            (
                &self.certificate_lag,
                "neutrin0_chunk_certificate_lag",
                "Complete certificate since the chunk's last slot start",
            ),
            (
                &self.certificate_stall,
                "neutrin0_chunk_certificate_stall",
                "Complete certificate past the chunk's last slot end (ok: none)",
            ),
            (
                &self.finality_lag,
                "neutrin0_chunk_finality_lag",
                "Durable finality since the chunk's last slot start",
            ),
        ] {
            stage.render(out, name, help);
        }
    }
}

#[cfg(test)]
mod tests;
