//! Mandatory sanction admission, FIFO execution and withdrawal holds.
//!
//! The execution shell verifies each SP1 receipt before calling the STF. The
//! SP1 block guest independently verifies those receipts through recursion.
//! This module checks statement bindings and owns all state mutations.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_runtime_core::StateBackend;

use crate::state::read_canonical;
use crate::{Address, GAS_SANCTION, Receipt, RuntimePolicy};

use neutrin0_runtime_abi::{AccountabilityOutput, RuntimeBlockInput, Sanction};

/// Runtime-owned durable totals of actual mandatory transfers.
pub mod settlement;
use settlement::SettlementAccumulator;

mod admission;
mod execution;
mod markers;

pub use markers::{marker_key, offence_key, slashed_key};

use admission::{check_policy, collect_admissions, enqueue_admissions};
use execution::execute_pending;
use markers::{record_expiry_bucket, sweep_expired_markers};

/// Runtime key for the bounded, consensus-ordered mandatory queue.
pub const QUEUE_KEY: &[u8] = b"accountability:queue";
/// Per-admission cost, separate from mandatory execution cost.
pub const GAS_EVIDENCE_ADMISSION: u64 = 10_000;
/// Absolute allocation bound, independent of a hostile claimed policy.
pub const MAX_PENDING: u32 = neutrin0_runtime_core::execution::MAX_EVIDENCE_ADMISSIONS;
/// Receipt kind of a framework evidence admission.
pub const EVIDENCE_RECEIPT_KIND: u8 = 7;
/// Receipt kind of a mandatory sanction execution, committed by the receipts
/// root.
///
/// A receipt's kind alone tells a sanction execution from an evidence
/// admission ([`EVIDENCE_RECEIPT_KIND`]).
pub const SANCTION_RECEIPT_KIND: u8 = 11;

/// Verified obligation; its fixed amount survives later policy changes.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct PendingSanction {
    /// Authenticated offence.
    pub sanction: Sanction,
    /// Deduction fixed at admission, clamped only by available slashable stake.
    pub amount: u128,
    /// Receipt-bound reward account, fixed at admission for safety sanctions.
    pub reporter: Option<Address>,
    /// Reporter share fixed at admission, independent of later policy changes.
    pub reporter_reward_bps: u16,
}

/// Read the bounded queue. Malformed authenticated state fails closed.
pub(crate) fn load_queue<B: StateBackend>(state: &mut B) -> Vec<PendingSanction> {
    read_canonical(state, QUEUE_KEY).unwrap_or_default()
}

/// Obligations waiting in the mandatory queue.
pub(crate) fn pending_count<B: StateBackend>(state: &mut B) -> usize {
    load_queue(state).len()
}

/// Bytes already in canonical borsh form.
///
/// Borsh decoding of the queue is strict (exact length, canonical `bool`,
/// `Option` and enum tags), so the stored bytes of a decoded queue are its
/// encoding and commit without a re-encoding round trip.
struct Encoded<'a>(&'a [u8]);

impl BorshSerialize for Encoded<'_> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(self.0)
    }
}

// The stored queue bytes and the decoded queue commit alike.
impl neutrin0_consensus_types::hashing::Committed for Encoded<'_> {
    const COMMITMENT_TAG: neutrin0_primitives::DomainTag =
        neutrin0_primitives::DOMAIN_SANCTION_QUEUE;
}

/// Offenders with obligations left in the mandatory FIFO, whose withdrawals
/// wait for them. Ordinary transactions never change the queue.
pub(crate) struct Backlog {
    /// Withdrawal accounts of the queued offenders.
    held: BTreeSet<Address>,
}

impl Backlog {
    pub(crate) fn of(queue: &[PendingSanction]) -> Self {
        Self {
            held: queue
                .iter()
                .map(|item| item.sanction.offender.withdrawal_credentials)
                .collect(),
        }
    }

    /// Pending deductions conservatively hold all withdrawals from their
    /// shared runtime account until the deterministic queue has processed
    /// them.
    pub(crate) fn holds(&self, address: &Address) -> bool {
        self.held.contains(address)
    }
}

/// Mandatory phase of a block, run before its ordinary transactions.
pub(crate) struct Mandatory {
    /// Block-proven accountability transition.
    pub(crate) output: AccountabilityOutput,
    /// Gas reserved for the executions.
    pub(crate) gas: u64,
    /// Autonomous execution receipts, in FIFO order.
    pub(crate) receipts: Vec<Receipt>,
}

/// Admit all proof-authenticated claims, then execute the mandatory FIFO prefix
/// before ordinary transactions. Returns reserved gas and autonomous receipts.
///
/// `policy` is the governed policy read at the start of the block; only
/// ordinary transactions can replace it. The execution shell has already
/// authenticated every evidence receipt and checked the input bindings.
pub(crate) fn apply<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
    policy: &RuntimePolicy,
) -> Mandatory {
    check_policy(input, policy);
    let stored = state.read(QUEUE_KEY);
    let mut queue: Vec<PendingSanction> = stored.as_deref().map_or_else(Vec::new, |bytes| {
        borsh::from_slice(bytes).expect("canonical sanction queue")
    });
    assert!(
        queue.len() <= policy.evidence_max_pending as usize,
        "queue bound"
    );
    let before = stored.as_deref().map_or_else(
        || {
            neutrin0_consensus_types::hashing::borsh_commitment(
                &neutrin0_primitives::DOMAIN_SANCTION_QUEUE,
                &queue,
            )
        },
        |bytes| commitment(&Encoded(bytes)),
    );
    sweep_expired_markers(
        state,
        input.block_height,
        input.evidence_anchor.unbonding_delay_blocks,
    );
    let admitted = collect_admissions(input, state);
    let execution_count =
        (queue.len() + admitted.len()).min(policy.evidence_executions_per_block as usize);
    // Existing obligations always have budget, even if the body is empty.
    let execution_gas = (execution_count as u64)
        .checked_mul(GAS_SANCTION)
        .expect("bounded execution gas");
    let admission_gas = (admitted.len() as u64)
        .checked_mul(GAS_EVIDENCE_ADMISSION)
        .expect("bounded admission gas");
    assert!(
        execution_gas
            .checked_add(admission_gas)
            .is_some_and(|gas| gas <= input.block_gas_limit),
        "mandatory sanction gas"
    );
    assert!(
        queue.len() + admitted.len() - execution_count <= policy.evidence_max_pending as usize,
        "queue capacity"
    );
    enqueue_admissions(state, input, policy, &admitted, &mut queue);
    record_expiry_bucket(state, input.block_height, &admitted);
    // Empty blocks leave totals untouched and need no witness entry for them.
    let settles = !admitted.is_empty() || execution_count > 0;
    let mut totals = if settles {
        settlement::load_totals(state)
    } else {
        settlement::SettlementTotals::default()
    };
    for sanction in &admitted {
        totals.admitted(sanction.kind);
    }
    let mut executed = Vec::with_capacity(execution_count);
    let mut receipts = Vec::with_capacity(execution_count);
    for item in queue.drain(..execution_count) {
        let status = execute_pending(state, &item, &mut totals);
        executed.push(item.sanction);
        receipts.push(Receipt {
            status_code: status.as_u32(),
            gas_used: GAS_SANCTION,
            kind: SANCTION_RECEIPT_KIND,
        });
    }
    if settles {
        settlement::store_totals(state, &totals);
    }
    let residual = borsh::to_vec(&queue).expect("canonical sanction queue");
    let after = commitment(&Encoded(&residual));
    if before != after {
        state.write(QUEUE_KEY, residual);
    }
    Mandatory {
        output: AccountabilityOutput {
            anchor: input.evidence_anchor,
            admitted,
            executed,
            queue_before: before,
            queue_after: after,
        },
        gas: execution_gas,
        receipts,
    }
}

#[cfg(test)]
mod reporter_tests;

#[cfg(test)]
pub(crate) mod tests;
