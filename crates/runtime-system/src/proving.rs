//! Proof-market escrow and settlement (design 08).
//!
//! The proposer keeps a block's tips, which pay for its own block proof. At
//! execution a block records, under the policy then in force, what its base
//! fee and the issuance accrued since the previous block owe: the base fee
//! split between the prover of the block's chunk and the chunk's
//! participating committee, half of the issuance for the prover of the
//! block's selected receipt and half for the chunk prover. The block
//! consuming the previous chunk's certificate settles every height of that
//! chunk's proving report: block issuance to each selected prover, the
//! committee share to the precommit signers by stake, and the chunk prover
//! share into the chunk's own escrow. Every chunk proof the report ratifies
//! is then paid that chunk's escrow, so a chunk prover is paid from the
//! blocks of the chunk it proved.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::proving::{NO_PROVING, ProvingReport};
use neutrin0_primitives::{Hash, SECONDS_PER_YEAR};
use neutrin0_runtime_core::StateBackend;

use crate::state::{
    BASIS_POINTS, RuntimePolicy, load_account, load_participation, prefixed_key, read_record,
    store_account, write_record,
};

/// Chunk id and commitment of the latest proving report the runtime settled.
pub const PROVING_KEY: &[u8] = b"consensus:proving";

/// Slot and timestamp of the latest executed block, from which issuance
/// accrues.
pub const ISSUANCE_CLOCK_KEY: &[u8] = b"issuance:clock";

/// Slots of issuance one block may accrue.
///
/// A longer gap accrues this many slots' worth and the rest is never minted,
/// so the block that replaces an abandoned height earns nothing for the slots
/// the height waited (design 08).
pub const MAX_ACCRUAL_SLOTS: u64 = 8;

#[derive(BorshDeserialize, BorshSerialize, Clone, Copy)]
struct IssuanceClock {
    slot: u64,
    timestamp: u64,
}

impl IssuanceClock {
    /// Seconds of issuance a block at `next` accrues after this one.
    /// Timestamps equal slot starts, so a gap of `slots` spans
    /// `elapsed / slots` seconds a slot.
    const fn accrual_secs(self, next: Self) -> u64 {
        let elapsed = next.timestamp.saturating_sub(self.timestamp);
        let slots = next.slot.saturating_sub(self.slot);
        if slots <= MAX_ACCRUAL_SLOTS {
            return elapsed;
        }
        elapsed / slots * MAX_ACCRUAL_SLOTS
    }
}

/// Gas charged per settlement payment.
pub(crate) const GAS_SETTLEMENT_PAYMENT: u64 = 100;

/// What a block owes the proof market, fixed at execution under the policy
/// then in force (design 08).
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FeeEscrow {
    /// Base fee owed to the chunk's participating committee.
    pub committee: u128,
    /// Base fee and chunk issuance owed to the prover of the block's chunk.
    pub chunk_prover: u128,
    /// Block issuance owed to the prover of the block's selected receipt.
    pub block_prover: u128,
}

/// State key of the escrow of `height`.
#[must_use]
pub fn escrow_fees_key(height: u64) -> Vec<u8> {
    prefixed_key(b"escrow:fees:", &height.to_be_bytes())
}

/// State key of the chunk prover share escrowed from chunk `chunk_id`'s
/// blocks, paid when that chunk proof is ratified.
#[must_use]
pub fn escrow_chunk_key(chunk_id: u64) -> Vec<u8> {
    prefixed_key(b"escrow:chunk:", &chunk_id.to_be_bytes())
}

/// Issuance accrued over `elapsed_secs` at `policy`'s annual rate on
/// `total_stake`. A gap longer than a year accrues one year.
#[must_use]
pub fn issuance_for(policy: &RuntimePolicy, total_stake: u128, elapsed_secs: u64) -> u128 {
    let annual = crate::mul_div_floor(
        total_stake,
        u128::from(policy.annual_issuance_bps.min(BASIS_POINTS)),
        u128::from(BASIS_POINTS),
    );
    crate::mul_div_floor(
        annual,
        u128::from(elapsed_secs.min(SECONDS_PER_YEAR)),
        u128::from(SECONDS_PER_YEAR),
    )
}

/// Record what the block at `height` owes the proof market (design 08).
///
/// That is `base_fees` split by the policy's chunk prover share, and the
/// issuance accrued at the policy's rate on the current total stake since the
/// previous block, over at most [`MAX_ACCRUAL_SLOTS`]. The caller passes the
/// block's candidate
/// record it already holds, whose stakes are that total. Every block writes
/// one, also with nothing owed. Settlement later pays exactly these amounts,
/// so a later policy change never reprices executed blocks.
pub fn record_block_fees<B: StateBackend>(
    state: &mut B,
    height: u64,
    context: &neutrin0_consensus_types::runtime::ConsensusExecutionContext,
    base_fees: u128,
    policy: &RuntimePolicy,
    candidates: &neutrin0_consensus_types::runtime::ConsensusCandidates,
) {
    let clock = IssuanceClock {
        slot: context.slot,
        timestamp: context.timestamp,
    };
    let previous: Option<IssuanceClock> = read_record(state, ISSUANCE_CLOCK_KEY);
    write_record(state, ISSUANCE_CLOCK_KEY, &clock);
    let elapsed = previous.map_or(0, |previous| previous.accrual_secs(clock));
    let total_stake = candidates.entries.iter().fold(0_u128, |total, candidate| {
        total.saturating_add(candidate.stake)
    });
    let issued = issuance_for(policy, total_stake, elapsed);
    let block_prover = issued / 2;
    let chunk_prover_fees = share(base_fees, policy.chunk_prover_fee_bps);
    write_record(
        state,
        &escrow_fees_key(height),
        &FeeEscrow {
            committee: base_fees - chunk_prover_fees,
            chunk_prover: chunk_prover_fees.saturating_add(issued - block_prover),
            block_prover,
        },
    );
}

/// The latest settled report's chunk id and commitment.
fn latest_settled<B: StateBackend>(state: &mut B) -> Option<(u64, Hash)> {
    read_record(state, PROVING_KEY)
}

/// `floor(value * bps / 10_000)`; `bps` is at most 10,000 under a valid
/// policy.
#[must_use]
pub fn share(value: u128, bps: u16) -> u128 {
    crate::mul_div_floor(
        value,
        u128::from(bps.min(BASIS_POINTS)),
        u128::from(BASIS_POINTS),
    )
}

/// Issue `amount` to `address`; nothing for an account the ledger cannot hold.
fn mint<B: StateBackend>(state: &mut B, address: &Hash, amount: u128) {
    if amount == 0 {
        return;
    }
    if state.mint_system_tokens(address, amount).is_some() {
        return;
    }
    let mut account = load_account(state, address);
    account.balance = account.balance.saturating_add(amount);
    store_account(state, address, &account);
}

/// Upper bound on the settlement gas of one report under `chunk_size`: one
/// payment per height, one per committee member, one per ratified chunk and
/// the chunk prover escrow write.
pub(crate) const fn settlement_gas_bound(chunk_size: u64) -> u64 {
    let payments = chunk_size
        .saturating_add(neutrin0_primitives::MAX_CONSENSUS_VALIDATORS as u64)
        .saturating_add(neutrin0_primitives::MAX_CHUNK_RATIFICATIONS as u64)
        .saturating_add(1);
    payments.saturating_mul(GAS_SETTLEMENT_PAYMENT)
}

/// Settle a strictly newer report and return the commitment the block commits
/// for its input, with the mandatory gas spent. Reports repeat in every block
/// of the consuming chunk; only the first settles. The participation report
/// of the same certificate, consumed just before, names who precommitted.
pub(crate) fn apply_proving<B: StateBackend>(
    state: &mut B,
    report: Option<&ProvingReport>,
) -> (Hash, u64) {
    // A block before the chunk's carrier commits the latest settled report.
    let Some(report) = report else {
        return (
            latest_settled(state).map_or(NO_PROVING, |(_, commitment)| commitment),
            0,
        );
    };
    if latest_settled(state).is_some_and(|(latest, _)| latest >= report.chunk_id) {
        return (report.commitment(), 0);
    }
    write_record(state, PROVING_KEY, &(report.chunk_id, report.commitment()));
    let present = load_participation(state)
        .filter(|participation| participation.chunk_id == report.chunk_id)
        .map(|participation| participation.present)
        .unwrap_or_default();
    let gas = settle(state, report, &present);
    (report.commitment(), gas)
}

fn settle<B: StateBackend>(state: &mut B, report: &ProvingReport, present: &[Hash]) -> u64 {
    let mut committee_total = 0_u128;
    let mut chunk_prover_escrow = 0_u128;
    for entry in &report.entries {
        let key = escrow_fees_key(entry.height);
        let escrow: FeeEscrow = read_record(state, &key).unwrap_or_default();
        state.delete(&key);
        mint(state, &entry.prover, escrow.block_prover);
        committee_total = committee_total.saturating_add(escrow.committee);
        chunk_prover_escrow = chunk_prover_escrow.saturating_add(escrow.chunk_prover);
    }
    // Only the committee members whose precommit the certificate carried
    // share the committee part, by stake; with none it is not issued.
    let participants: Vec<&(Hash, u128)> = report
        .committee
        .iter()
        .filter(|(address, _)| present.contains(address))
        .collect();
    // Stakes are wei and the shares exact, so the shares never exceed the
    // escrowed total; a total beyond `u128` cannot come from a bounded set.
    let eligible = participants
        .iter()
        .try_fold(0_u128, |total, (_, weight)| total.checked_add(*weight))
        .unwrap_or(0);
    if eligible > 0 {
        for (address, weight) in &participants {
            mint(
                state,
                address,
                crate::mul_div_floor(committee_total, *weight, eligible),
            );
        }
    }
    // This chunk's prover share waits for this chunk's proof to be ratified,
    // which a later report carries; the proofs this report ratifies are of
    // earlier chunks, whose escrow already exists.
    let escrowed = chunk_prover_escrow > 0;
    if escrowed {
        write_record(
            state,
            &escrow_chunk_key(report.chunk_id),
            &chunk_prover_escrow,
        );
    }
    for (chunk_id, prover) in &report.chunk_provers {
        let key = escrow_chunk_key(*chunk_id);
        let held: u128 = read_record(state, &key).unwrap_or(0);
        state.delete(&key);
        mint(state, prover, held);
    }
    let payments = report
        .entries
        .len()
        .saturating_add(participants.len())
        .saturating_add(report.chunk_provers.len())
        .saturating_add(usize::from(escrowed));
    u64::try_from(payments)
        .unwrap_or(u64::MAX)
        .saturating_mul(GAS_SETTLEMENT_PAYMENT)
}

#[cfg(test)]
mod tests;
