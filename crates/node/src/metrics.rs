//! Prometheus text-format metrics over a minimal HTTP listener.
//!
//! The node records proving outcomes and latencies as they happen and samples
//! chain, sync and BFT state once per second. The exposition is rendered by
//! hand and served by a tiny HTTP/1.1 responder independently of JSON-RPC.

use std::sync::atomic::AtomicU64;

mod http;
mod render;
mod stage;

pub(crate) use http::serve;
pub use http::{MAX_CONNECTIONS, SNAPSHOT_INTERVAL, bind};
pub use render::render;
pub(crate) use stage::{LatencyHistogram, counter, family, gauge, labeled, loads, seconds};
pub use stage::{StageMetrics, StageTimer};

/// Histogram bucket upper bounds in seconds, chosen for proof latencies that
/// range from a few seconds (blocks) to many minutes (chunks on CPU).
pub const LATENCY_BUCKETS_SECS: [f64; 17] = [
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
    1800.0,
];

/// Process-lifetime counters updated at the proving and production sites.
#[derive(Debug, Default)]
pub struct NodeMetrics {
    /// Queueing, admission and optional proof stages.
    pub proof_pipeline: crate::proof_metrics::ProofMetrics,
    /// Reporter retention, submission and finalized economic state.
    pub reporter: crate::reporter_metrics::ReporterMetrics,
    /// Execution, imports, transaction admission and BFT events.
    pub execution: crate::execution_metrics::ExecutionMetrics,
    /// Locally dispatched block workers, including budget waiters.
    pub block_proof_queue_launched: AtomicU64,
    /// Block proofs produced by this node.
    pub block_proofs: StageMetrics,
    /// Complete consensus chunk proofs produced by this node.
    pub chunk_proofs: StageMetrics,
    /// Blocks produced by the local proposer.
    pub blocks_produced: AtomicU64,
    /// Block proof jobs waiting for a worker.
    pub block_proof_queue_pending: AtomicU64,
}

impl NodeMetrics {
    /// Attempt counters and latencies of one proving stage.
    #[must_use]
    pub const fn proof_stage(&self, stage: crate::proof_metrics::ProofStage) -> &StageMetrics {
        use crate::proof_metrics::ProofStage;
        match stage {
            ProofStage::Block => &self.block_proofs,
            ProofStage::Chunk => &self.chunk_proofs,
            ProofStage::Fact => &self.proof_pipeline.fact_proofs,
            ProofStage::Evidence => &self.proof_pipeline.evidence_proofs,
            ProofStage::ProgramSetup => &self.proof_pipeline.program_setups,
        }
    }
}

/// One live BFT session as seen by the engine.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent phase flags exported as gauges"
)]
pub struct BftSessionGauge {
    /// Eligible stake represented by this session.
    pub total_stake: u128,
    /// Value prevote stake accumulated in the current round.
    pub prevote_stake: u128,
    /// Value precommit stake accumulated in the current round.
    pub precommit_stake: u128,
    /// Explicit nil prevote stake in the current round.
    pub nil_prevote_stake: u128,
    /// Explicit nil precommit stake in the current round.
    pub nil_precommit_stake: u128,
    /// Chunk under vote.
    pub chunk_id: u64,
    /// Current round.
    pub round: u32,
    /// Local validator has prevoted.
    pub local_prevoted: bool,
    /// Local validator has precommitted.
    pub local_precommitted: bool,
    /// A prevote quorum has been observed.
    pub prevote_quorum: bool,
    /// A precommit quorum has been observed.
    pub precommit_quorum: bool,
}

/// Chain, sync and consensus state sampled at scrape time.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent operational conditions exported as gauges"
)]
pub struct MetricsSnapshot {
    /// An authenticated current validator list is locally available.
    pub validator_set_available: bool,
    /// Total seats, including zero-weight and permanently ejected identities.
    pub validator_seats: u64,
    /// Unfinalised head height.
    pub head_height: u64,
    /// Pending certificate boundary height, or zero when none is retained.
    pub certified_execution_height: u64,
    /// Executed blocks above the complete-proof finalized boundary.
    pub execution_ahead_blocks: u64,
    /// Seconds since the pending certificate was durably authenticated.
    pub execution_certification_age_seconds: u64,
    /// Ordinary production has filled its authenticated execution window.
    pub execution_backpressure: bool,
    /// Number of finalized chunks; the latest chunk receipt proves all of them.
    pub finalized_chunks: u64,
    /// Chunks whose raw data may have been pruned.
    pub pruned_before_chunk: u64,
    /// Number of unslashed, positive-weight consensus validators.
    pub active_validators: u64,
    /// Connected peers, if a sync driver is attached.
    pub peers: u64,
    /// Sync driver has not reached the live-following state.
    pub syncing: bool,
    /// Sync FSM has not yet had a first peer handshake.
    pub sync_awaiting_peer: bool,
    /// Full-node snapshot bootstrap has not installed authenticated state yet.
    pub bootstrap_pending: bool,
    /// Proof-only node's locally authenticated weak-subjectivity anchor expired.
    pub trust_anchor_expired: bool,
    /// Two verified History proofs disagree; the light client halted.
    pub history_conflict: bool,
    /// The data filesystem is below its free-space quota.
    pub storage_pressure: bool,
    /// A message signed by the local key that this node did not sign paused
    /// signing and production.
    pub doppelganger: bool,
    /// Governance enacted a program switch that has not activated yet.
    pub upgrade_scheduled: bool,
    /// Programs of the scheduled switch this node has not installed.
    pub upgrade_missing_programs: u64,
    /// Buffered mempool transactions.
    pub mempool: u64,
    /// Live BFT sessions.
    pub bft_sessions: Vec<BftSessionGauge>,
}

/// Anything that can be scraped: the chain backend in production, a stub in tests.
pub trait MetricsSource: Send + Sync {
    /// Counters updated by the node's workers.
    fn metrics(&self) -> &NodeMetrics;
    /// Sample live state. Called by the supervised health monitor once per second.
    fn snapshot(&self) -> MetricsSnapshot;
    /// Append subsystem exposition that only scrapes need. Called on a blocking
    /// thread at most once per [`SNAPSHOT_INTERVAL`], never by the health monitor.
    fn render_subsystems(&self, _out: &mut String) {}
}

#[cfg(test)]
mod tests;
