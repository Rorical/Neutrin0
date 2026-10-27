//! Journaled projection of native system records and balances into REVM state.

use super::RuntimeContext;
use crate::{
    addresses,
    state::{consensus_address, ethereum_address},
};
use alloc::vec::Vec;
use neutrin0_runtime_core::StateBackend;
use revm::context_interface::{ContextTr, JournalTr};
use revm::primitives::{Address, U256};

pub(super) struct JournalBackend<'a, 'b, B: StateBackend> {
    pub(super) context: &'a mut RuntimeContext<'b, B>,
    pub(super) caller: Address,
    pub(super) gas: u64,
    pub(super) limit: u64,
    pub(super) exhausted: bool,
}

impl<B: StateBackend> JournalBackend<'_, '_, B> {
    pub(super) const fn charge(&mut self, gas: u64) -> bool {
        self.gas = self.gas.saturating_add(gas);
        self.exhausted |= self.gas > self.limit;
        !self.exhausted
    }
    fn slot(&mut self, key: &[u8], part: Option<usize>) -> U256 {
        self.context.db_mut().system_slot(key, part)
    }
    fn read_slot(&mut self, key: &[u8], part: Option<usize>) -> U256 {
        if !self.charge(100) {
            return U256::ZERO;
        }
        let slot = self.slot(key, part);
        self.context
            .journal_mut()
            .load_account(addresses::SYSTEM_STATE)
            .expect("system account");
        self.context
            .journal_mut()
            .sload(addresses::SYSTEM_STATE, slot)
            .expect("system storage")
            .data
    }
    fn write_slot(&mut self, key: &[u8], part: Option<usize>, value: U256) {
        if !self.charge(1_000) {
            return;
        }
        let slot = self.slot(key, part);
        self.context
            .journal_mut()
            .load_account(addresses::SYSTEM_STATE)
            .expect("system account");
        self.context
            .journal_mut()
            .sstore(addresses::SYSTEM_STATE, slot, value)
            .expect("system storage");
    }
    fn balance(&mut self, address: Address) -> U256 {
        if !self.charge(100) {
            return U256::ZERO;
        }
        self.context
            .journal_mut()
            .load_account(address)
            .expect("canonical EVM account")
            .data
            .info
            .balance
    }
    fn transfer(&mut self, from: Address, to: Address, amount: U256) {
        if amount.is_zero() {
            return;
        }
        if !self.charge(1_000) {
            return;
        }
        let result = self
            .context
            .journal_mut()
            .transfer(from, to, amount)
            .expect("canonical balance transfer");
        assert!(result.is_none(), "system transfer backed by checked funds");
    }
}

impl<B: StateBackend> StateBackend for JournalBackend<'_, '_, B> {
    fn authenticated_caller(&self) -> Option<[u8; 32]> {
        Some(consensus_address(self.caller))
    }
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(bytes) = key.strip_prefix(neutrin0_runtime_system::ACCOUNT_KEY_PREFIX)
            && let Ok(address) = <&[u8; 32]>::try_from(bytes)
        {
            let balance =
                self.balance(ethereum_address(address).expect("canonical Ethereum system account"));
            return Some(
                borsh::to_vec(&neutrin0_runtime_system::Account {
                    balance: balance.min(U256::from(u128::MAX)).to::<u128>(),
                })
                .expect("system account"),
            );
        }
        let length = self.read_slot(key, None);
        if length == U256::ZERO {
            return None;
        }
        assert!(
            length <= U256::from(8 * 1024 * 1024 + 1),
            "bounded system record"
        );
        let length = length.to::<usize>();
        let length = length - 1;
        let read_gas = u64::try_from(length.div_ceil(32)).expect("bounded words") * 100;
        if self.gas.saturating_add(read_gas) > self.limit {
            self.exhausted = true;
            return None;
        }
        let mut bytes = Vec::with_capacity(length.div_ceil(32) * 32);
        for part in 0..length.div_ceil(32) {
            bytes.extend_from_slice(&self.read_slot(key, Some(part)).to_be_bytes::<32>());
        }
        bytes.truncate(length);
        Some(bytes)
    }
    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        if let Some(bytes) = key.strip_prefix(neutrin0_runtime_system::ACCOUNT_KEY_PREFIX)
            && let Ok(address) = <&[u8; 32]>::try_from(bytes)
        {
            let address = ethereum_address(address).expect("canonical Ethereum system account");
            let previous = self.balance(address);
            let virtual_balance = previous.min(U256::from(u128::MAX)).to::<u128>();
            let account: neutrin0_runtime_system::Account =
                borsh::from_slice(&value).expect("canonical system account");
            if account.balance < virtual_balance {
                self.transfer(
                    address,
                    addresses::ESCROW,
                    U256::from(virtual_balance - account.balance),
                );
            } else {
                self.transfer(
                    addresses::ESCROW,
                    address,
                    U256::from(account.balance - virtual_balance),
                );
            }
            return;
        }
        assert!(value.len() <= 8 * 1024 * 1024, "bounded system record");
        let write_gas = u64::try_from(value.len().div_ceil(32) + 1).expect("bounded words") * 1_000;
        if self.gas.saturating_add(write_gas) > self.limit {
            self.exhausted = true;
            return;
        }
        self.write_slot(key, None, U256::from(value.len() + 1));
        for (part, chunk) in value.chunks(32).enumerate() {
            let mut word = [0; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            self.write_slot(key, Some(part), U256::from_be_bytes(word));
        }
    }
    fn delete(&mut self, key: &[u8]) {
        self.write_slot(key, None, U256::ZERO);
    }
    fn pre_state_root(&self) -> [u8; 32] {
        self.context.db().state.pre_state_root()
    }
    fn post_state_root(&self) -> [u8; 32] {
        self.pre_state_root()
    }
    fn credit_system_tokens(&mut self, address: &[u8; 32], amount: u128) -> Option<u128> {
        let address = ethereum_address(address).expect("canonical withdrawal address");
        if addresses::RESERVED.contains(&address) {
            return Some(0);
        }
        let balance = self.balance(address);
        let credit = U256::from(amount).min(U256::MAX - balance).to::<u128>();
        self.transfer(addresses::ESCROW, address, U256::from(credit));
        Some(credit)
    }
}
