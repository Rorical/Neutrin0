//! Adapter between shared u128 staking operations and Ethereum's U256 account ledger.

use crate::state::{EvmAccount, ethereum_address, load_account, store_account};
use alloc::vec::Vec;
use neutrin0_runtime_core::StateBackend;
use revm::primitives::U256;

/// Shared-system account operations over the native EVM ledger.
pub struct SystemCurrency<'a, B> {
    /// Authenticated underlying state or disposable journal.
    pub state: &'a mut B,
}

impl<B: StateBackend> StateBackend for SystemCurrency<'_, B> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(bytes) = key.strip_prefix(neutrin0_runtime_system::ACCOUNT_KEY_PREFIX)
            && let Ok(credentials) = <&[u8; 32]>::try_from(bytes)
        {
            let address =
                ethereum_address(credentials).expect("canonical Ethereum withdrawal account");
            let record = load_account(self.state, address)
                .expect("canonical account")
                .unwrap_or_default();
            let balance = U256::from_be_bytes(record.balance)
                .min(U256::from(u128::MAX))
                .to::<u128>();
            return Some(
                borsh::to_vec(&neutrin0_runtime_system::Account { balance })
                    .expect("system account"),
            );
        }
        self.state.read(key)
    }
    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        if let Some(bytes) = key.strip_prefix(neutrin0_runtime_system::ACCOUNT_KEY_PREFIX)
            && let Ok(credentials) = <&[u8; 32]>::try_from(bytes)
        {
            let address =
                ethereum_address(credentials).expect("canonical Ethereum withdrawal account");
            let mut record = load_account(self.state, address)
                .expect("canonical account")
                .unwrap_or_default();
            let previous = U256::from_be_bytes(record.balance);
            let virtual_balance = previous.min(U256::from(u128::MAX)).to::<u128>();
            let updated: neutrin0_runtime_system::Account =
                borsh::from_slice(&value).expect("canonical system account");
            let balance = if updated.balance >= virtual_balance {
                previous.checked_add(U256::from(updated.balance - virtual_balance))
            } else {
                previous.checked_sub(U256::from(virtual_balance - updated.balance))
            }
            .expect("system account arithmetic");
            record.balance = balance.to_be_bytes();
            // EVM alone owns Ethereum nonces; system operations do not spend another nonce.
            store_account(self.state, address, &record);
            return;
        }
        self.state.write(key, value);
    }
    fn delete(&mut self, key: &[u8]) {
        self.state.delete(key);
    }
    fn pre_state_root(&self) -> [u8; 32] {
        self.state.pre_state_root()
    }
    fn post_state_root(&self) -> [u8; 32] {
        self.state.post_state_root()
    }
    fn credit_system_tokens(&mut self, credentials: &[u8; 32], amount: u128) -> Option<u128> {
        let Ok(address) = ethereum_address(credentials) else {
            return Some(0);
        };
        if crate::addresses::RESERVED.contains(&address) {
            return Some(0);
        }
        let mut record = load_account(self.state, address)
            .expect("canonical account")
            .unwrap_or_else(EvmAccount::default);
        let balance = U256::from_be_bytes(record.balance);
        let credited = U256::from(amount).min(U256::MAX - balance).to::<u128>();
        record.balance = (balance + U256::from(credited)).to_be_bytes();
        let mut escrow = load_account(self.state, crate::addresses::ESCROW)
            .expect("canonical escrow")
            .expect("initialized escrow");
        escrow.balance = U256::from_be_bytes(escrow.balance)
            .checked_sub(U256::from(credited))
            .expect("rewards backed by collateral")
            .to_be_bytes();
        store_account(self.state, crate::addresses::ESCROW, &escrow);
        store_account(self.state, address, &record);
        Some(credited)
    }
    fn mint_system_tokens(&mut self, credentials: &[u8; 32], amount: u128) -> Option<u128> {
        let Ok(address) = ethereum_address(credentials) else {
            return Some(0);
        };
        if crate::addresses::RESERVED.contains(&address) {
            return Some(0);
        }
        let mut record = load_account(self.state, address)
            .expect("canonical account")
            .unwrap_or_else(EvmAccount::default);
        let balance = U256::from_be_bytes(record.balance);
        let minted = U256::from(amount).min(U256::MAX - balance).to::<u128>();
        record.balance = (balance + U256::from(minted)).to_be_bytes();
        store_account(self.state, address, &record);
        Some(minted)
    }
    fn burn_system_tokens(&mut self, amount: u128) {
        if amount == 0 {
            return;
        }
        let mut escrow = load_account(self.state, crate::addresses::ESCROW)
            .expect("canonical escrow")
            .expect("initialized escrow");
        escrow.balance = U256::from_be_bytes(escrow.balance)
            .checked_sub(U256::from(amount))
            .expect("deduction backed by collateral")
            .to_be_bytes();
        store_account(self.state, crate::addresses::ESCROW, &escrow);
    }
}
