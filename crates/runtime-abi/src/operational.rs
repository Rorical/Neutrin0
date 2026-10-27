//! Shared operational contracts implemented by every installable runtime.
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history_proof::ProgramArtifacts;
use neutrin0_primitives::{BlsPublicKey, Hash, ProgramSet};

/// Program-distribution query; returns `Vec<ProgramDistribution>`.
///
/// Args are the next block's borsh `EvidenceAnchor`, of which only the chunk,
/// unbonding delay and chunk size are read, so only proposals still live
/// there count.
pub const QUERY_PROGRAMS: &str = "runtime:programs";
/// Resource and retention query; no args, returns `EvidencePolicy`.
pub const QUERY_EVIDENCE_POLICY: &str = "runtime:evidence_policy";
/// Coverage query; args `Vec<EvidenceCoverageRequest>`, returns one status per request.
pub const QUERY_EVIDENCE_COVERAGE: &str = "runtime:evidence_coverage";
/// Transaction selection; args `RuntimeBlockInput`, returns user-envelope indexes.
pub const QUERY_SELECT_TRANSACTIONS: &str = "runtime:select_transactions";
/// Remaining runtime liability for tracked consensus identities.
///
/// Args `ReporterStatusRequest`; returns `Vec<ReporterStatus>` in request
/// order. Reporters should query an authenticated finalized state before
/// deleting historical sources.
pub const QUERY_METHOD_REPORTER_STATUS: &str = "reporter_status";
/// Durable sanction settlements and bounded FIFO counts; no args, returns
/// `SettlementSnapshot`.
///
/// Querying finalized state excludes speculative executions and survives
/// restart and authenticated state bootstrap without replaying old block
/// bodies.
pub const QUERY_METHOD_ACCOUNTABILITY_METRICS: &str = "accountability_metrics";
/// Maximum coverage and reporter identities per operational query.
pub const MAX_REPORTER_STATUS_IDENTITIES: usize = 256;

/// Governed artifact identities currently proposed or scheduled for installation.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProgramDistribution {
    /// Governance has enacted this schedule; open proposals may be archived but not warmed.
    pub enacted: bool,
    /// Governance-declared identities; hosts derive and check them before installation.
    pub programs: ProgramSet,
    /// BLAKE3 content hashes of the distributed WASM and Guest ELFs.
    pub artifacts: ProgramArtifacts,
}

/// Runtime-owned retention and mandatory resource policy needed by the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidencePolicy {
    /// Liveness admission age; safety claims never expire through this field.
    pub evidence_max_age_blocks: u64,
    /// Maximum retained FIFO obligations.
    pub evidence_max_pending: u32,
    /// Maximum evidence admissions in one block.
    pub evidence_admissions_per_block: u32,
    /// Maximum FIFO executions in one block.
    pub evidence_executions_per_block: u32,
    /// Current mandatory FIFO size.
    pub pending_count: u32,
    /// Gas reserved per admission.
    pub admission_gas: u64,
    /// Gas reserved per FIFO execution.
    pub execution_gas: u64,
    /// Deduction for a proven abandoned height; zero disables the offence.
    pub abandonment_penalty_amount: u128,
}

/// Explicit coverage question using an authenticated historical identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceCoverageRequest {
    /// Safety identity; zero can be used when only an offence is queried.
    pub identity: BlsPublicKey,
    /// Optional exact offence identity.
    pub offence_id: Option<Hash>,
    /// Optional source chunk and withdrawal account for certified non-participation.
    pub liveness: Option<(u64, Hash)>,
}
/// Runtime response in request order. Missing responses never authorize deletion.
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent verdicts are reported together, one per request."
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EvidenceCoverage {
    /// A positive precommit acknowledgement covers the requested source and identity.
    pub participated: bool,
    /// Permanent safety sanction covers this BLS identity.
    pub tombstoned: bool,
    /// Exact offence is already admitted in live execution state.
    pub admitted: bool,
    /// Certified participation permits this liveness admission.
    pub liveness_eligible: bool,
}

/// Historical consensus identity and its authenticated runtime account.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReporterIdentity {
    /// Stable consensus signing identity.
    pub pubkey: BlsPublicKey,
    /// Runtime account the historical identity's sanctions deduct from.
    pub withdrawal_credentials: Hash,
}

/// Bounded batch of identities whose local sources a reporter retains.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ReporterStatusRequest {
    /// Identities obtained from authenticated historical validator sets.
    pub identities: Vec<ReporterIdentity>,
}

/// Runtime-owned economic lifecycle of one tracked consensus identity.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReporterStatus {
    /// Exact identity supplied by the reporter.
    pub identity: ReporterIdentity,
    /// Remaining deductible stake plus funds still in the withdrawal queue.
    /// Mature but unclaimed withdrawals remain deductible in this runtime.
    pub slashable_balance: u128,
    /// A permanent safety admission already covers this identity.
    pub tombstoned: bool,
    /// A mandatory queue entry against this identity remains unexecuted.
    pub pending: bool,
}

/// A checked cumulative counter that cannot interrupt mandatory sanctions.
///
/// Once the mathematical total exceeds `u128::MAX`, `value` stays at the maximum
/// and `overflowed` makes the loss of precision explicit. No funds depend on it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementCounter {
    /// Exact total until overflow, then the representable lower bound.
    pub value: u128,
    /// The mathematical cumulative total exceeded the representation.
    pub overflowed: bool,
}

/// Completed economic effects for one fixed sanction kind.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementKindTotals {
    /// Proof-authenticated obligations admitted, including zero-balance offences.
    pub admitted: SettlementCounter,
    /// Mandatory obligations executed, including zero deductions.
    pub executed: SettlementCounter,
    /// Executions which actually deducted no funds.
    pub zero_deductions: SettlementCounter,
    /// Funds actually removed from stake and unclaimed withdrawal queues.
    pub deducted: SettlementCounter,
    /// Spendable funds actually credited to proof-bound reporter accounts.
    pub rewarded: SettlementCounter,
    /// Deducted funds not credited, including unrepresentable reward residue.
    pub burned: SettlementCounter,
}

/// Durable cumulative economics of the installed runtime, restored by snapshots.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementTotals {
    /// Safety sanctions, admitted once per BLS identity.
    pub slash: SettlementKindTotals,
    /// Certificate non-inclusion sanctions.
    pub inactivity: SettlementKindTotals,
    /// Abandoned-height sanctions.
    pub abandonment: SettlementKindTotals,
}

/// Constant-size query result; queued counts describe obligations, never estimated funds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SettlementSnapshot {
    /// Authenticated, cumulative completed accounting.
    pub totals: SettlementTotals,
    /// Safety obligations waiting in the mandatory FIFO.
    pub pending_slash: u32,
    /// Inactivity obligations waiting in the mandatory FIFO.
    pub pending_inactivity: u32,
    /// Abandonment obligations waiting in the mandatory FIFO.
    pub pending_abandonment: u32,
}
