//! Validator records, the stake-holding set view, recent bonds and BLS
//! registrations.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_runtime_core::StateBackend;

use super::{
    bonding_key, load_consensus_candidates, read_record, registration_key, validator_key,
    write_record,
};
use crate::Address;

/// Per-validator state stored under `validator_key(addr)`.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Validator {
    /// Stake currently locked behind this validator; the validator
    /// participates in consensus exactly while it is positive.
    pub stake: u128,
}

/// Borsh-encode a validator record for storage.
#[must_use]
pub fn encode_validator(validator: &Validator) -> Vec<u8> {
    borsh::to_vec(validator).expect("borsh encode Validator never fails")
}

pub(crate) fn load_validator<B: StateBackend>(state: &mut B, addr: &Address) -> Validator {
    load_validator_record(state, addr).unwrap_or_default()
}

/// `addr`'s validator record, or `None` when the runtime holds none.
///
/// Only genesis and [`SystemAction::Register`](crate::system::SystemAction::Register)
/// create a record; stake adds to an existing one.
pub(crate) fn load_validator_record<B: StateBackend>(
    state: &mut B,
    addr: &Address,
) -> Option<Validator> {
    read_record(state, &validator_key(addr))
}

pub(crate) fn store_validator<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    validator: &Validator,
) {
    write_record(state, &validator_key(addr), validator);
}

/// One row of the canonical [`ValidatorSet`] record.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValidatorSetEntry {
    /// Validator runtime account.
    pub address: Address,
    /// Current stake amount.
    pub stake: u128,
}

/// The validators holding stake, sorted by address ascending. A view, never
/// stored: see `load_validator_set`.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorSet {
    /// Active validators sorted by address ascending.
    pub entries: Vec<ValidatorSetEntry>,
}

impl ValidatorSet {
    /// Insert or replace `addr`'s entry. Maintains the sorted invariant.
    pub fn upsert(&mut self, addr: Address, stake: u128) {
        match self.entries.binary_search_by(|e| e.address.cmp(&addr)) {
            Ok(idx) => self.entries[idx].stake = stake,
            Err(idx) => self.entries.insert(
                idx,
                ValidatorSetEntry {
                    address: addr,
                    stake,
                },
            ),
        }
    }

    /// Remove `addr` from the set if present. Returns `true` when the
    /// removal actually changed the set.
    pub fn remove(&mut self, addr: &Address) -> bool {
        if let Ok(idx) = self.entries.binary_search_by(|e| e.address.cmp(addr)) {
            self.entries.remove(idx);
            true
        } else {
            false
        }
    }

    /// Sum of all entries' stakes, saturating at `u128::MAX`.
    ///
    /// Saturating like [`WithdrawalQueue::total`](super::WithdrawalQueue::total)
    /// and the governance vote
    /// tally, so the total of a subset never exceeds the total of the set and
    /// every build agrees: a plain sum would panic natively, where overflow
    /// checks are on, but wrap in the SP1 Guest, where they are off.
    #[must_use]
    pub fn total_stake(&self) -> u128 {
        self.entries
            .iter()
            .fold(0_u128, |total, entry| total.saturating_add(entry.stake))
    }
}

/// The validators holding stake. Each stake lives in its validator record and
/// is mirrored once, into the consensus candidate record every block already
/// reads; candidates without stake are left out.
pub(crate) fn load_validator_set<B: StateBackend>(state: &mut B) -> ValidatorSet {
    ValidatorSet {
        entries: load_consensus_candidates(state)
            .entries
            .into_iter()
            .filter(|candidate| candidate.stake > 0)
            .map(|candidate| ValidatorSetEntry {
                address: candidate.address,
                stake: candidate.stake,
            })
            .collect(),
    }
}

/// Stake recently added to a validator, stored under [`bonding_key`].
///
/// Governance does not count `amount` until
/// [`UPGRADE_VOTER_MIN_AGE_BLOCKS`](crate::governance::UPGRADE_VOTER_MIN_AGE_BLOCKS)
/// blocks have passed since `since_height`, the latest addition. Stake
/// writes it; the stake a registration bonds is covered by the
/// registration's own age instead.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Bonding {
    /// Stake added since the record last matured.
    pub amount: u128,
    /// Height of the latest addition.
    pub since_height: u64,
}

pub(crate) fn load_bonding<B: StateBackend>(state: &mut B, addr: &Address) -> Option<Bonding> {
    read_record(state, &bonding_key(addr))
}

pub(crate) fn store_bonding<B: StateBackend>(state: &mut B, addr: &Address, bonding: &Bonding) {
    write_record(state, &bonding_key(addr), bonding);
}

/// Per-validator registration record stored under [`registration_key`].
///
/// Recorded by [`SystemAction::Register`](crate::system::SystemAction::Register),
/// consumed by the chunk validator transition and deleted once the validator
/// has fully withdrawn.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorRegistration {
    /// Runtime address of the registered validator. Doubles as the
    /// `withdrawal_credentials` of the consensus-side
    /// [`neutrin0_primitives::Validator`] entry derived by the chunk.
    pub address: Address,
    /// BLS12-381 G1 compressed public key (min-pk POP scheme).
    pub bls_pubkey: neutrin0_primitives::BlsPublicKey,
    /// BLS proof-of-possession over
    /// [`registration_pop_message(bls_pubkey, address)`](neutrin0_primitives::registration_pop_message).
    /// The runtime stores this as opaque bytes; the complete chunk validator
    /// transition verifies it under the
    /// `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` DST before lifting the
    /// registration into the consensus active validator set.
    pub pop_signature: neutrin0_primitives::BlsSignature,
    /// Height of the block that registered the validator. Governance
    /// weights only registrations older than a minimum age, so freshly
    /// deposited stake cannot steer an upgrade before it can even vote in
    /// consensus.
    pub registered_at_height: u64,
}

/// Read `addr`'s registration record, if one is stored.
pub fn load_validator_registration<B: StateBackend>(
    state: &mut B,
    addr: &Address,
) -> Option<ValidatorRegistration> {
    read_record(state, &registration_key(addr))
}

pub(crate) fn store_validator_registration<B: StateBackend>(
    state: &mut B,
    registration: &ValidatorRegistration,
) {
    write_record(
        state,
        &registration_key(&registration.address),
        registration,
    );
}
