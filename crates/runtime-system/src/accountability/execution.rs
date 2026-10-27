//! Execution of one queued obligation: the deduction, the reporter's share
//! of it and the burn of the rest.

use neutrin0_consensus_types::evidence::SanctionKind;
use neutrin0_runtime_core::StateBackend;

use super::PendingSanction;
use super::settlement::{self, SettlementAccumulator};
use crate::staking::apply_deduction;
use crate::state::{BASIS_POINTS, load_account, store_account};
use crate::{Address, ReceiptStatus};

/// Complete one mandatory obligation, paying only from its actual deduction.
/// Zero slashable balance is an explicit outcome, never a retry loop.
pub(super) fn execute_pending<B: StateBackend>(
    state: &mut B,
    item: &PendingSanction,
    totals: &mut settlement::SettlementTotals,
) -> ReceiptStatus {
    let result = apply_deduction(
        state,
        &item.sanction.offender.withdrawal_credentials,
        item.amount,
    );
    let (status, deducted, rewarded) = match result {
        Ok(deducted) => {
            let rewarded = if item.sanction.kind == SanctionKind::Slash
                && let Some(reporter) = item.reporter
            {
                credit_reporter(state, &reporter, deducted, item.reporter_reward_bps)
            } else {
                0
            };
            (ReceiptStatus::Success, deducted, rewarded)
        }
        Err(ReceiptStatus::InsufficientBalance) => (ReceiptStatus::InsufficientBalance, 0, 0),
        Err(error) => panic!("unexpected mandatory deduction failure: {error:?}"),
    };
    totals.executed(item.sanction.kind, deducted, rewarded);
    state.burn_system_tokens(deducted - rewarded);
    state.write(&item.sanction.marker_key(), alloc::vec![1]);
    if item.sanction.kind == SanctionKind::Slash {
        crate::staking::forget_tombstoned_identity(state, &item.sanction.offender.pubkey);
    }
    status
}

/// Move a bounded share of the actual deduction into spendable funds. The
/// remainder burns; neither a requested penalty nor an empty balance mints a
/// reward. Quotient/remainder arithmetic avoids overflowing on a full slash.
pub(super) fn credit_reporter<B: StateBackend>(
    state: &mut B,
    reporter: &Address,
    deducted: u128,
    basis_points: u16,
) -> u128 {
    assert!(
        basis_points <= BASIS_POINTS,
        "canonical reporter reward share"
    );
    let reward = crate::mul_div_floor(deducted, u128::from(basis_points), u128::from(BASIS_POINTS));
    if reward == 0 {
        return 0;
    }
    if let Some(credited) = state.credit_system_tokens(reporter, reward) {
        return credited;
    }
    let mut account = load_account(state, reporter);
    // Saturation burns any unrepresentable residue rather than blocking the
    // mandatory FIFO or increasing supply beyond the deducted funds.
    let credited = reward.min(u128::MAX - account.balance);
    account.balance += credited;
    store_account(state, reporter, &account);
    credited
}
