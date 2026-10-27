//! The system view of runtime accounts.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_runtime_core::StateBackend;

use super::{account_key, read_record, write_record};
use crate::Address;

/// The system view of an account under `account_key(addr)`: its spendable
/// balance in wei. The runtime backs it with the execution account; transaction
/// nonces belong to the execution engine.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Account {
    /// Spendable balance in wei.
    pub balance: u128,
}

/// Borsh-encode an account record for storage.
#[must_use]
pub fn encode_account(account: &Account) -> Vec<u8> {
    borsh::to_vec(account).expect("borsh encode Account never fails")
}

/// Borsh-decode an account record from storage, or `None` on failure.
#[must_use]
pub fn decode_account(bytes: &[u8]) -> Option<Account> {
    Account::try_from_slice(bytes).ok()
}

pub(crate) fn load_account<B: StateBackend>(state: &mut B, addr: &Address) -> Account {
    read_record(state, &account_key(addr)).unwrap_or_default()
}

pub(crate) fn store_account<B: StateBackend>(state: &mut B, addr: &Address, account: &Account) {
    write_record(state, &account_key(addr), account);
}
