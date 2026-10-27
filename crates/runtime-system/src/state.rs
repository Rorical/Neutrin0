//! Runtime state records, their key layout and typed accessors.

#![allow(
    clippy::redundant_pub_crate,
    reason = "Accessors stay explicitly crate-scoped inside this private module."
)]

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_runtime_core::StateBackend;

use crate::Address;

mod accounts;
mod consensus;
mod policy;
mod validators;
mod withdrawals;

pub use accounts::{Account, decode_account, encode_account};
pub(crate) use accounts::{load_account, store_account};
pub(crate) use consensus::{
    GAS_PARTICIPATION_ACK, apply_participation, apply_participation_acks, liveness_eligible,
    participation_acknowledged, store_consensus_candidates,
};
pub use consensus::{load_consensus_candidates, load_participation};
pub(crate) use policy::{
    BASIS_POINTS, activate_pending_policy, store_pending_policy, store_runtime_policy,
};
pub use policy::{
    PENDING_POLICY_KEY, POLICY_DELAY_CHUNKS, PendingPolicy, RuntimePolicy, load_pending_policy,
    load_runtime_policy, policy_delay_blocks,
};
pub use validators::{
    Bonding, Validator, ValidatorRegistration, ValidatorSet, ValidatorSetEntry, encode_validator,
    load_validator_registration,
};
pub(crate) use validators::{
    load_bonding, load_validator, load_validator_record, load_validator_set, store_bonding,
    store_validator, store_validator_registration,
};
pub use withdrawals::{Withdrawal, WithdrawalQueue};
pub(crate) use withdrawals::{load_withdrawal_queue, store_withdrawal_queue};

// ---------------------------------------------------------------------------
// Key layout
// ---------------------------------------------------------------------------

/// Prefix used to derive state keys for account records:
/// `account_key(addr) = ACCOUNT_KEY_PREFIX || addr`.
pub const ACCOUNT_KEY_PREFIX: &[u8; 5] = b"acct:";
/// Prefix used to derive state keys for validator records:
/// `validator_key(addr) = VALIDATOR_KEY_PREFIX || addr`.
pub const VALIDATOR_KEY_PREFIX: &[u8; 4] = b"val:";
/// Prefix used to derive state keys for per-validator withdrawal
/// queues: `withdrawal_key(addr) = WITHDRAWAL_KEY_PREFIX || addr`.
/// Each key holds a borsh-encoded [`WithdrawalQueue`].
pub const WITHDRAWAL_KEY_PREFIX: &[u8; 4] = b"wdr:";
/// Prefix used to derive state keys for per-validator registration
/// records: `registration_key(addr) = REGISTRATION_KEY_PREFIX || addr`.
/// Each key holds a borsh-encoded [`ValidatorRegistration`].
pub const REGISTRATION_KEY_PREFIX: &[u8; 4] = b"reg:";
/// Prefix used to derive state keys for per-validator bonding records:
/// `bonding_key(addr) = BONDING_KEY_PREFIX || addr`. Each key holds a
/// borsh-encoded [`Bonding`].
pub const BONDING_KEY_PREFIX: &[u8; 5] = b"bond:";
/// Canonical key holding the governable [`RuntimePolicy`]. Genesis seeds it
/// from the chain specification; governance replaces it (design 20).
pub const RUNTIME_POLICY_KEY: &[u8] = b"runtime:policy";
/// Canonical key of the latest certified [`ParticipationReport`] the runtime
/// consumed, available to reward and liveness rules.
///
/// [`ParticipationReport`]: neutrin0_consensus_types::participation::ParticipationReport
pub const PARTICIPATION_KEY: &[u8] = b"consensus:participation";
/// Prefix of the per-chunk certified absence lists.
///
/// `absent_key(chunk_id) = ABSENT_KEY_PREFIX || chunk_id BE8`. Each key holds
/// the `absent` addresses of that chunk's [`ParticipationReport`] while
/// liveness evidence against the chunk is admissible.
///
/// [`ParticipationReport`]: neutrin0_consensus_types::participation::ParticipationReport
pub const ABSENT_KEY_PREFIX: &[u8] = b"consensus:absent:";

/// `prefix || suffix`, the layout of every prefixed runtime key.
pub(crate) fn prefixed_key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}

/// Build the state key for `addr`.
#[must_use]
pub fn account_key(addr: &Address) -> Vec<u8> {
    prefixed_key(ACCOUNT_KEY_PREFIX, addr)
}

/// Build the state key for `addr`.
#[must_use]
pub fn validator_key(addr: &Address) -> Vec<u8> {
    prefixed_key(VALIDATOR_KEY_PREFIX, addr)
}

/// Build the registration-record state key for `addr`.
#[must_use]
pub fn registration_key(addr: &Address) -> Vec<u8> {
    prefixed_key(REGISTRATION_KEY_PREFIX, addr)
}

/// Build the state key for `addr`.
#[must_use]
pub fn withdrawal_key(addr: &Address) -> Vec<u8> {
    prefixed_key(WITHDRAWAL_KEY_PREFIX, addr)
}

/// Build the certified-absence key of `chunk_id`.
#[must_use]
pub fn absent_key(chunk_id: u64) -> Vec<u8> {
    prefixed_key(ABSENT_KEY_PREFIX, &chunk_id.to_be_bytes())
}

/// Build the bonding-record state key for `addr`.
#[must_use]
pub fn bonding_key(addr: &Address) -> Vec<u8> {
    prefixed_key(BONDING_KEY_PREFIX, addr)
}

// ---------------------------------------------------------------------------
// Typed access
// ---------------------------------------------------------------------------

/// Decode the record stored under `key`.
///
/// Absent or undecodable bytes read as `None`: the lenient behavior of every
/// record that falls back to its default.
pub(crate) fn read_record<T: BorshDeserialize, B: StateBackend>(
    state: &mut B,
    key: &[u8],
) -> Option<T> {
    state
        .read(key)
        .and_then(|bytes| T::try_from_slice(&bytes).ok())
}

/// Decode the record stored under `key`, failing closed: authenticated bytes
/// that do not decode canonically abort the transition.
pub(crate) fn read_canonical<T: BorshDeserialize, B: StateBackend>(
    state: &mut B,
    key: &[u8],
) -> Option<T> {
    state
        .read(key)
        .map(|bytes| borsh::from_slice(&bytes).expect("canonical runtime record"))
}

/// Store the canonical encoding of `value` under `key`.
pub(crate) fn write_record<T: BorshSerialize, B: StateBackend>(
    state: &mut B,
    key: &[u8],
    value: &T,
) {
    state.write(
        key,
        borsh::to_vec(value).expect("borsh encoding into memory never fails"),
    );
}

#[cfg(test)]
mod participation_tests;
