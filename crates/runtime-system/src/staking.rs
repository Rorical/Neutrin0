//! Staking actions, the validator lifecycle and mandatory stake deductions.
//!
//! Every action runs on behalf of the caller its enclosing engine
//! authenticated; the engine charges gas and rolls the action back on
//! failure. Each handler holds every check up to its first state mutation
//! and rechecks the authenticated committee handoff and capacity against
//! the block that executes it.

#![allow(
    clippy::redundant_pub_crate,
    reason = "Transaction handlers stay explicitly crate-scoped inside this private module."
)]

mod actions;
mod checks;
mod deduction;
mod records;
mod registration;

pub(crate) use actions::{apply_stake, apply_unstake, apply_voluntary_exit, apply_withdraw};
pub(crate) use deduction::apply_deduction;
pub use records::prune_consensus_candidates;
pub(crate) use records::{forget_tombstoned_identity, hold_offender};
pub(crate) use registration::{apply_register_validator, apply_rotate_key};

/// Block facts every staking action executes against.
pub(crate) struct StakingContext<'a> {
    /// Height of the executing block.
    pub(crate) block_height: u64,
    /// Genesis-fixed unbonding delay, in blocks.
    pub(crate) unbonding_delay: u64,
    /// Governed minimum stake a validator may hold other than zero.
    pub(crate) min_validator_stake: u128,
    /// The block's authenticated consensus validator set.
    pub(crate) active: &'a [neutrin0_primitives::Validator],
}

#[cfg(test)]
mod handoff_tests;
