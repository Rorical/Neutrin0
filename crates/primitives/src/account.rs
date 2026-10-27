//! Runtime accounts: the 32-byte form of an address the runtime can pay.

use crate::Hash;

/// Whether a 32-byte runtime account names an account the runtime can pay./// Whether a 32-byte runtime account names an account the runtime can pay.
///
/// Such an account is twelve zero bytes, then the 20-byte Ethereum address.
/// The runtime credits nothing to any other value, so every prover, reporter
/// and withdrawal destination the protocol records must have this form.
#[must_use]
pub fn is_runtime_account(account: &Hash) -> bool {
    account[..12] == [0; 12]
}

/// The runtime account of a 20-byte Ethereum address: twelve zero bytes,
/// then the address.
#[must_use]
pub const fn runtime_account(address: [u8; 20]) -> Hash {
    let mut account = [0; 32];
    let mut index = 0;
    while index < address.len() {
        account[12 + index] = address[index];
        index += 1;
    }
    account
}
