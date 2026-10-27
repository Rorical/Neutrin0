//! Stake, unstake, voluntary exit and withdrawal.

use neutrin0_runtime_core::StateBackend;

use super::StakingContext;
use super::checks::{
    authenticate, check_bond, check_bondable, check_exit_handoff, require_amount, require_bonded,
};
use super::records::{commit_validator, retire_validator, unbond};
use crate::accountability::Backlog;
use crate::state::{
    Withdrawal, load_account, load_validator, load_withdrawal_queue, store_account,
    store_withdrawal_queue, withdrawal_key,
};
use crate::{Address, ReceiptStatus};

/// Add `amount` of the caller's balance to its own validator record.
pub(crate) fn apply_stake<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    validator: &Address,
    amount: u128,
) -> Result<(), ReceiptStatus> {
    authenticate(state, validator)?;
    let (mut funder, bonded) = check_bond(state, context, validator, validator, amount)?;
    check_bondable(state, validator, context.active)?;
    funder.balance -= amount;
    store_account(state, validator, &funder);
    commit_validator(state, validator, &bonded);
    crate::governance::record_bond(state, validator, amount, context.block_height);
    Ok(())
}

/// Queue `amount` of the caller's stake for delayed withdrawal. A partial
/// unstake may not leave the validator below the governed minimum.
pub(crate) fn apply_unstake<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    validator: &Address,
    amount: u128,
) -> Result<(), ReceiptStatus> {
    authenticate(state, validator)?;
    require_amount(amount)?;
    let record = load_validator(state, validator);
    if record.stake < amount {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    require_bonded(record.stake - amount, context.min_validator_stake)?;
    check_exit_handoff(state, validator, record.stake - amount, context.active)?;
    let mature_at_height = context
        .block_height
        .checked_add(context.unbonding_delay)
        .ok_or(ReceiptStatus::Overflow)?;
    unbond(
        state,
        validator,
        record,
        Withdrawal {
            amount,
            mature_at_height,
        },
    );
    Ok(())
}

/// Queue the caller's entire current stake for delayed withdrawal.
pub(crate) fn apply_voluntary_exit<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    validator: &Address,
) -> Result<(), ReceiptStatus> {
    authenticate(state, validator)?;
    let record = load_validator(state, validator);
    if record.stake == 0 {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    check_exit_handoff(state, validator, 0, context.active)?;
    let mature_at_height = context
        .block_height
        .checked_add(context.unbonding_delay)
        .ok_or(ReceiptStatus::Overflow)?;
    let amount = record.stake;
    unbond(
        state,
        validator,
        record,
        Withdrawal {
            amount,
            mature_at_height,
        },
    );
    Ok(())
}

/// Credit the caller's matured withdrawal entries, unless a pending sanction
/// holds the account. Succeeds with nothing credited when no entry matured.
pub(crate) fn apply_withdraw<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    backlog: &Backlog,
    validator: &Address,
) -> Result<(), ReceiptStatus> {
    authenticate(state, validator)?;
    // Matured funds stay locked until the mandatory queue has processed
    // every obligation against this account.
    if backlog.holds(validator) {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    let mut queue = load_withdrawal_queue(state, validator);

    // Partition into matured / pending. Maturity is monotonic in insertion
    // order, so a single split point exists, but the scan is defensive
    // against a queue carrying entries from a different unbonding delay.
    let mut matured: u128 = 0;
    queue.entries.retain(|entry| {
        let mature = entry.mature_at_height <= context.block_height;
        if mature {
            matured = matured.saturating_add(entry.amount);
        }
        !mature
    });

    if let Some(credited) = state.credit_system_tokens(validator, matured) {
        if credited != matured {
            return Err(ReceiptStatus::Overflow);
        }
    } else {
        let mut account = load_account(state, validator);
        account.balance = account
            .balance
            .checked_add(matured)
            .ok_or(ReceiptStatus::Overflow)?;
        store_account(state, validator, &account);
    }
    // Drop the queue entirely when it's empty so the trie footprint
    // stays minimal. The witness builder's `Trie::collect_path_nodes`
    // emits the sibling node at every on-path Branch, so the SP1
    // guest's `Trie::remove` has the data it needs to call
    // `absorb_into_parent` (the trie's collapse path).
    if !queue.entries.is_empty() {
        store_withdrawal_queue(state, validator, &queue);
        return Ok(());
    }
    // Nothing is queued any more. A validator with no stake left has
    // served its full unbonding delay, so every record can go.
    let record = load_validator(state, validator);
    if record.stake == 0 {
        retire_validator(state, validator);
    } else {
        state.delete(&withdrawal_key(validator));
    }
    Ok(())
}
