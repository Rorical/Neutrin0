//! The state interface every STF is generic over.

use alloc::vec::Vec;

use neutrin0_primitives::StateRoot;

/// Read/write state interface used by every STF.
///
/// Backends implement this differently for the proven path
/// ([`WitnessState`](crate::WitnessState)) and the dynamic path
/// ([`host::TracingState`](crate::host::TracingState)),
/// but the STF code itself is identical.
pub trait StateBackend {
    /// Caller already authenticated by a runtime-owned execution engine.
    /// Witness and host backends return `None`; only an executing runtime may provide it.
    fn authenticated_caller(&self) -> Option<neutrin0_primitives::Hash> {
        None
    }

    /// Credit system funds through a runtime's wider account ledger, when present.
    /// Returns the actual credit; `None` selects the native account representation.
    fn credit_system_tokens(
        &mut self,
        _address: &neutrin0_primitives::Hash,
        _amount: u128,
    ) -> Option<u128> {
        None
    }

    /// Burn actual deducted collateral in runtimes with an explicit escrow account.
    fn burn_system_tokens(&mut self, _amount: u128) {}

    /// Issue new tokens to `address` through a runtime's wider account ledger,
    /// when present (design 08). Returns the actual amount issued, zero for an
    /// address the ledger cannot hold; `None` selects the native account
    /// representation.
    fn mint_system_tokens(
        &mut self,
        _address: &neutrin0_primitives::Hash,
        _amount: u128,
    ) -> Option<u128> {
        None
    }
    /// Read the value at `key`, or `None` if the key is absent.
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>>;

    /// Set the value at `key`.
    fn write(&mut self, key: &[u8], value: Vec<u8>);

    /// Remove `key` from the state if present.
    fn delete(&mut self, key: &[u8]);

    /// Trie root of the state before any writes this run made.
    fn pre_state_root(&self) -> StateRoot;

    /// Trie root of the state including writes from this run.
    fn post_state_root(&self) -> StateRoot;
}
