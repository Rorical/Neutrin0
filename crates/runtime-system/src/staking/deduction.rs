//! Mandatory stake deductions.

use neutrin0_runtime_core::StateBackend;

use super::records::commit_validator;
use crate::state::{load_validator, load_withdrawal_queue, store_withdrawal_queue, withdrawal_key};
use crate::{Address, ReceiptStatus};

/// Deduct up to `amount` from `address`'s slashable balance and return the
/// actual deduction.
pub(crate) fn apply_deduction<B: StateBackend>(
    state: &mut B,
    address: &Address,
    amount: u128,
) -> Result<u128, ReceiptStatus> {
    let mut validator = load_validator(state, address);
    let mut queue = load_withdrawal_queue(state, address);

    // Total slashable = active stake + queued unbonding.  Queued
    // entries stay slashable until they mature into the spendable
    // balance via `apply_withdraw`, which closes the
    // unstake-then-detect-then-slash front-running gap: a
    // validator who notices their own misbehaviour cannot
    // pre-emptively `Unstake` to hide stake from the impending
    // slash.  The spendable account balance is intentionally
    // never touched — funds that have already left the staking
    // lifecycle are out of reach of the slashing penalty.
    let total_slashable = validator.stake.saturating_add(queue.total());
    if total_slashable == 0 {
        // Nothing to burn. A never-deposited address has zero stake and
        // an empty queue, so it reports the same error code.
        return Err(ReceiptStatus::InsufficientBalance);
    }

    let burn = total_slashable.min(amount);

    // Burn from active stake first.  Stake is the primary
    // slashable asset; the queue is a secondary source consumed
    // only when stake is exhausted.
    let burn_from_stake = validator.stake.min(burn);
    validator.stake -= burn_from_stake;
    let mut remaining_burn = burn - burn_from_stake;

    // Then burn FIFO from the unbonding queue.  Oldest entries
    // burn first: they were unstaked at the earliest opportunity,
    // so they reflect the validator's earliest known intent to
    // exit and are the most plausible front-running targets.  A
    // partially-burned entry preserves its `mature_at_height` so
    // the residue still observes the unbonding delay.
    let queue_touched = remaining_burn > 0 && !queue.entries.is_empty();
    if queue_touched {
        queue.entries.retain_mut(|entry| {
            if remaining_burn == 0 {
                return true;
            }
            if entry.amount <= remaining_burn {
                // Entry burned in full — drop it.
                remaining_burn -= entry.amount;
                return false;
            }
            entry.amount -= remaining_burn;
            remaining_burn = 0;
            true
        });
    }

    commit_validator(state, address, &validator);
    // Touch the queue key only when we actually changed it, so the
    // witness footprint stays minimal for the common
    // "slash a non-unstaking validator" case.
    if queue_touched {
        if queue.entries.is_empty() {
            state.delete(&withdrawal_key(address));
        } else {
            store_withdrawal_queue(state, address, &queue);
        }
    }
    Ok(burn)
}
