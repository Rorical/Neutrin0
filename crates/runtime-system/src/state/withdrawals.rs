//! Per-validator unbonding queues.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_runtime_core::StateBackend;

use super::{read_record, withdrawal_key, write_record};
use crate::Address;

/// Single queued unbonding entry.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct Withdrawal {
    /// Amount queued for withdrawal.
    pub amount: u128,
    /// Block height at which `amount` becomes claimable. The STF
    /// admits the claim when the block being executed has
    /// `block_height >= mature_at_height`.
    pub mature_at_height: u64,
}

/// Per-validator FIFO queue of unbonding entries.
///
/// Stored under `withdrawal_key(addr)` and never stored empty: a withdrawal
/// or mandatory deduction that removes the last entry deletes the key, as
/// does retiring the validator. The witness carries the sibling nodes those
/// deletions need, so an absent key is how state records an empty queue.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct WithdrawalQueue {
    /// Pending entries in FIFO insertion order. Maturity never decreases
    /// along the queue because every entry created in block `H` matures at
    /// `H + input.unbonding_delay_blocks`, which no earlier entry exceeds.
    pub entries: Vec<Withdrawal>,
}

impl WithdrawalQueue {
    /// Sum of every entry's `amount`. Saturating addition keeps the
    /// total well-defined even on contrived oversized queues.
    #[must_use]
    pub fn total(&self) -> u128 {
        let mut total: u128 = 0;
        for entry in &self.entries {
            total = total.saturating_add(entry.amount);
        }
        total
    }
}

pub(crate) fn load_withdrawal_queue<B: StateBackend>(
    state: &mut B,
    addr: &Address,
) -> WithdrawalQueue {
    read_record(state, &withdrawal_key(addr)).unwrap_or_default()
}

pub(crate) fn store_withdrawal_queue<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    queue: &WithdrawalQueue,
) {
    write_record(state, &withdrawal_key(addr), queue);
}
