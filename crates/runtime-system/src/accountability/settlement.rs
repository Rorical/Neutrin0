//! Constant-size, runtime-owned accounting of completed sanction transfers.

use neutrin0_consensus_types::evidence::SanctionKind;
use neutrin0_runtime_core::StateBackend;

use crate::state::{read_canonical, write_record};

/// Authenticated cumulative settlement record. Its size never grows with offences.
pub const SETTLEMENT_TOTALS_KEY: &[u8] = b"accountability:settlement_totals";

pub use neutrin0_runtime_abi::operational::{
    SettlementCounter, SettlementKindTotals, SettlementSnapshot, SettlementTotals,
};

trait CounterAccumulator {
    fn add(&mut self, amount: u128);
}
impl CounterAccumulator for SettlementCounter {
    fn add(&mut self, amount: u128) {
        if let Some(value) = self.value.checked_add(amount) {
            self.value = value;
        } else {
            self.value = u128::MAX;
            self.overflowed = true;
        }
    }
}

const fn kind_mut(totals: &mut SettlementTotals, kind: SanctionKind) -> &mut SettlementKindTotals {
    match kind {
        SanctionKind::Slash => &mut totals.slash,
        SanctionKind::Inactivity => &mut totals.inactivity,
        SanctionKind::Abandonment => &mut totals.abandonment,
    }
}

pub(super) trait SettlementAccumulator {
    fn admitted(&mut self, kind: SanctionKind);
    fn executed(&mut self, kind: SanctionKind, deducted: u128, rewarded: u128);
}
impl SettlementAccumulator for SettlementTotals {
    fn admitted(&mut self, kind: SanctionKind) {
        kind_mut(self, kind).admitted.add(1);
    }

    fn executed(&mut self, kind: SanctionKind, deducted: u128, rewarded: u128) {
        let totals = kind_mut(self, kind);
        totals.executed.add(1);
        totals.zero_deductions.add(u128::from(deducted == 0));
        totals.deducted.add(deducted);
        totals.rewarded.add(rewarded);
        totals.burned.add(
            deducted
                .checked_sub(rewarded)
                .expect("reward comes from deduction"),
        );
    }
}

/// Load authenticated cumulative totals. Absent genesis state means no settlements.
pub fn load_totals<B: StateBackend>(state: &mut B) -> SettlementTotals {
    read_canonical(state, SETTLEMENT_TOTALS_KEY).unwrap_or_default()
}

/// Read completed transfers and pending obligations without changing runtime state.
pub fn snapshot<B: StateBackend>(state: &mut B) -> SettlementSnapshot {
    let mut result = SettlementSnapshot {
        totals: load_totals(state),
        ..SettlementSnapshot::default()
    };
    let queue = super::load_queue(state);
    assert!(
        queue.len() <= super::MAX_PENDING as usize,
        "canonical sanction queue bound"
    );
    for pending in queue {
        let count = match pending.sanction.kind {
            SanctionKind::Slash => &mut result.pending_slash,
            SanctionKind::Inactivity => &mut result.pending_inactivity,
            SanctionKind::Abandonment => &mut result.pending_abandonment,
        };
        *count = count.checked_add(1).expect("bounded sanction count");
    }
    result
}

pub(super) fn store_totals<B: StateBackend>(state: &mut B, totals: &SettlementTotals) {
    write_record(state, SETTLEMENT_TOTALS_KEY, totals);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observational_counter_overflow_is_explicit_and_does_not_wrap() {
        let mut counter = SettlementCounter {
            value: u128::MAX - 1,
            overflowed: false,
        };
        counter.add(1);
        assert_eq!(counter.value, u128::MAX);
        assert!(!counter.overflowed);
        counter.add(1);
        counter.add(2);
        assert_eq!(counter.value, u128::MAX);
        assert!(counter.overflowed);
    }
}
