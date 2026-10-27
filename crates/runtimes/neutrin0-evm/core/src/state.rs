//! Ethereum account and storage access through authenticated Neutrin0 state.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use neutrin0_runtime_core::StateBackend;
use revm::bytecode::Bytecode;
use revm::primitives::{
    Address, AddressMap, B256, KECCAK_EMPTY, StorageKey, StorageValue, U256, keccak256,
};
use revm::state::{Account, AccountInfo, EvmStorage};
use revm::{Database, DatabaseCommit};

pub use neutrin0_runtime_abi::ethereum::EvmAccount;

/// Convert an Ethereum address into consensus withdrawal credentials.
pub fn consensus_address(address: Address) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    bytes
}

/// Reject noncanonical Ethereum withdrawal credentials.
pub fn ethereum_address(bytes: &[u8; 32]) -> Result<Address, StateError> {
    if bytes[..12] != [0; 12] {
        return Err(StateError("noncanonical Ethereum address"));
    }
    Ok(Address::from_slice(&bytes[12..]))
}

/// Key of an Ethereum account.
pub fn account_key(address: Address) -> Vec<u8> {
    key(b"evm:account:", address.as_slice())
}
/// Key of content-addressed Ethereum bytecode.
pub fn code_key(hash: B256) -> Vec<u8> {
    key(b"evm:code:", hash.as_slice())
}
/// Key of an Ethereum storage slot.
pub fn storage_key(address: Address, index: U256) -> Vec<u8> {
    let mut bytes = account_key(address);
    bytes.extend_from_slice(&index.to_be_bytes::<32>());
    bytes
}
fn key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(prefix);
    bytes.extend_from_slice(suffix);
    bytes
}

/// Failure to read canonical authenticated EVM state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateError(pub &'static str);
impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl core::error::Error for StateError {}
impl revm::database_interface::DBErrorMarker for StateError {}

/// Read one Ethereum account, distinguishing absence from malformed state.
pub fn load_account<B: StateBackend>(
    state: &mut B,
    address: Address,
) -> Result<Option<EvmAccount>, StateError> {
    state
        .read(&account_key(address))
        .map(|bytes| {
            borsh::from_slice(&bytes).map_err(|_| StateError("malformed Ethereum account"))
        })
        .transpose()
}

/// Store a canonical Ethereum account.
pub fn store_account<B: StateBackend>(state: &mut B, address: Address, account: &EvmAccount) {
    state.write(
        &account_key(address),
        borsh::to_vec(account).expect("canonical EVM account"),
    );
}

/// REVM database backed by the same witnessed state operations in every target.
pub struct StateDb<'a, B> {
    /// Authenticated state backend.
    pub state: &'a mut B,
    /// Height at which BLOCKHASH executes.
    pub height: u64,
    pub(crate) system_slots: BTreeMap<U256, SystemSlot>,
    system_records: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    code_cache: Option<&'a mut VerifiedBytecodeCache>,
}

/// Bounded, block-local cache of authenticated content-addressed bytecode.
/// It carries no account, warm-access, transient-storage or transaction journal state.
#[derive(Default)]
pub(crate) struct VerifiedBytecodeCache {
    entries: BTreeMap<B256, Bytecode>,
    bytes: usize,
}

impl VerifiedBytecodeCache {
    fn get(&self, hash: &B256) -> Option<&Bytecode> {
        self.entries.get(hash)
    }

    fn insert(&mut self, hash: B256, code: Bytecode) {
        const MAX_ENTRIES: usize = 256;
        const MAX_BYTES: usize = 8 * 1024 * 1024;
        // Include a conservative allowance for padding, jump maps and metadata.
        let weight = code.len().saturating_mul(2).saturating_add(512);
        if weight > MAX_BYTES || self.entries.contains_key(&hash) {
            return;
        }
        if self.entries.len() == MAX_ENTRIES || self.bytes > MAX_BYTES - weight {
            self.entries.clear();
            self.bytes = 0;
        }
        self.entries.insert(hash, code);
        self.bytes += weight;
    }
}

/// Native record projection used only by the runtime-owned precompile journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SystemSlot {
    pub(crate) key: Vec<u8>,
    pub(crate) part: Option<usize>,
}

impl<'a, B> StateDb<'a, B> {
    /// Open the witnessed EVM database for one execution height.
    pub const fn new(state: &'a mut B, height: u64) -> Self {
        Self {
            state,
            height,
            system_slots: BTreeMap::new(),
            system_records: BTreeMap::new(),
            code_cache: None,
        }
    }

    pub(crate) fn with_code_cache(
        state: &'a mut B,
        height: u64,
        code_cache: &'a mut VerifiedBytecodeCache,
    ) -> Self {
        Self {
            code_cache: Some(code_cache),
            ..Self::new(state, height)
        }
    }
    pub(crate) fn system_slot(&mut self, key: &[u8], part: Option<usize>) -> U256 {
        let mut bytes = Vec::from(&b"NTRO/system-record"[..]);
        bytes.extend_from_slice(&(key.len() as u64).to_le_bytes());
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&part.map_or(0_u64, |index| index as u64 + 1).to_le_bytes());
        let slot = U256::from_be_bytes(keccak256(bytes).0);
        let descriptor = SystemSlot {
            key: key.to_vec(),
            part,
        };
        if let Some(previous) = self.system_slots.insert(slot, descriptor.clone()) {
            assert_eq!(previous, descriptor, "system slot collision");
        }
        slot
    }
}

impl<B: StateBackend> Database for StateDb<'_, B> {
    type Error = StateError;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, StateError> {
        Ok(
            load_account(self.state, address)?.map(|record| AccountInfo {
                nonce: record.nonce,
                balance: U256::from_be_bytes(record.balance),
                code_hash: B256::from(record.code_hash),
                code: None,
                ..AccountInfo::default()
            }),
        )
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, StateError> {
        if hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        if let Some(code) = self
            .code_cache
            .as_deref()
            .and_then(|cache| cache.get(&hash))
        {
            return Ok(code.clone());
        }
        let bytes = self
            .state
            .read(&code_key(hash))
            .ok_or(StateError("missing witnessed bytecode"))?;
        if keccak256(&bytes) != hash {
            return Err(StateError("bytecode hash mismatch"));
        }
        let code = Bytecode::new_raw_checked(bytes.into())
            .map_err(|_| StateError("malformed Ethereum delegation bytecode"))?;
        if let Some(cache) = self.code_cache.as_deref_mut() {
            cache.insert(hash, code.clone());
        }
        Ok(code)
    }
    fn storage(&mut self, address: Address, index: StorageKey) -> Result<StorageValue, StateError> {
        if address == crate::addresses::SYSTEM_STATE {
            let descriptor = self
                .system_slots
                .get(&index)
                .ok_or(StateError("unregistered system slot"))?;
            let state = &mut *self.state;
            let value = self
                .system_records
                .entry(descriptor.key.clone())
                .or_insert_with(|| state.read(&descriptor.key));
            return Ok(descriptor.part.map_or_else(
                || U256::from(value.as_ref().map_or(0, |bytes| bytes.len() + 1)),
                |part| {
                    let mut word = [0; 32];
                    if let Some(bytes) = value.as_ref()
                        && let Some(suffix) = bytes.get(part * 32..)
                    {
                        let length = suffix.len().min(32);
                        word[..length].copy_from_slice(&suffix[..length]);
                    }
                    U256::from_be_bytes(word)
                },
            ));
        }
        let Some(bytes) = self.state.read(&storage_key(address, index)) else {
            return Ok(U256::ZERO);
        };
        let word: [u8; 32] = bytes
            .try_into()
            .map_err(|_| StateError("malformed storage word"))?;
        Ok(U256::from_be_bytes(word))
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, StateError> {
        if number >= self.height || self.height - number > 256 {
            return Ok(B256::ZERO);
        }
        let Some(bytes) = self.state.read(&block_hash_key(number % 256)) else {
            return Err(StateError("missing block history"));
        };
        let (height, hash): (u64, [u8; 32]) =
            borsh::from_slice(&bytes).map_err(|_| StateError("malformed block history"))?;
        if height != number {
            return Err(StateError("stale block history"));
        }
        Ok(hash.into())
    }
}

impl<B: StateBackend> DatabaseCommit for StateDb<'_, B> {
    fn commit(&mut self, changes: AddressMap<Account>) {
        // REVM finalizes Cancun/Osaka SELFDESTRUCT semantics before this commit.
        for (address, account) in changes {
            if !account.is_touched() {
                continue;
            }
            if account.is_selfdestructed() || account.is_empty() {
                self.state.delete(&account_key(address));
                continue;
            }
            if let Some(code) = &account.info.code {
                self.commit_bytecode(account.info.code_hash, code);
            }
            store_account(
                self.state,
                address,
                &EvmAccount {
                    nonce: account.info.nonce,
                    balance: account.info.balance.to_be_bytes(),
                    code_hash: account.info.code_hash.0,
                },
            );
            if address == crate::addresses::SYSTEM_STATE {
                self.commit_system_records(account.storage);
                continue;
            }
            self.commit_storage(address, account.storage);
        }
    }
}

impl<B: StateBackend> StateDb<'_, B> {
    fn commit_bytecode(&mut self, code_hash: B256, code: &Bytecode) {
        let bytes = code.original_byte_slice();
        let already_stored = self
            .code_cache
            .as_deref()
            .and_then(|cache| cache.get(&code_hash))
            .is_some_and(|stored| stored.original_byte_slice() == bytes);
        if !bytes.is_empty() && !already_stored {
            assert_eq!(keccak256(bytes), code_hash, "canonical bytecode hash");
            self.state.write(&code_key(code_hash), bytes.to_vec());
            if let Some(cache) = self.code_cache.as_deref_mut() {
                cache.insert(code_hash, code.clone());
            }
        }
    }

    fn commit_system_records(&mut self, storage: EvmStorage) {
        let mut records: BTreeMap<Vec<u8>, Vec<(Option<usize>, U256)>> = BTreeMap::new();
        for (slot, value) in storage {
            if !value.is_changed() {
                continue;
            }
            let descriptor = self
                .system_slots
                .get(&slot)
                .expect("registered system journal write");
            records
                .entry(descriptor.key.clone())
                .or_default()
                .push((descriptor.part, value.present_value));
        }
        for (key, words) in records {
            let old = self.state.read(&key);
            let length = words
                .iter()
                .find_map(|(part, value)| part.is_none().then_some(*value))
                .unwrap_or_else(|| U256::from(old.as_ref().map_or(0, |bytes| bytes.len() + 1)));
            if length == U256::ZERO {
                self.state.delete(&key);
                continue;
            }
            // Bounded before conversion, so both pointer widths agree.
            assert!(
                length <= U256::from(8 * 1024 * 1024 + 1),
                "system record memory bound"
            );
            let length = length.to::<usize>();
            let mut bytes = old.unwrap_or_default();
            bytes.resize(length - 1, 0);
            for (part, value) in words {
                let Some(part) = part else {
                    continue;
                };
                if let Some(suffix) = bytes.get_mut(part * 32..) {
                    let length = suffix.len().min(32);
                    suffix[..length].copy_from_slice(&value.to_be_bytes::<32>()[..length]);
                }
            }
            self.state.write(&key, bytes);
        }
    }

    fn commit_storage(&mut self, address: Address, storage: EvmStorage) {
        for (slot, value) in storage {
            if !value.is_changed() {
                continue;
            }
            let key = storage_key(address, slot);
            if value.present_value.is_zero() {
                self.state.delete(&key);
            } else {
                self.state
                    .write(&key, value.present_value.to_be_bytes::<32>().to_vec());
            }
        }
    }
}

/// Bounded ring key retaining the latest 256 native block hashes.
pub fn block_hash_key(index: u64) -> Vec<u8> {
    key(b"evm:block_hash:", &index.to_be_bytes())
}

/// Read a canonical runtime-owned record.
pub fn read_record<T: BorshDeserialize, B: StateBackend>(
    state: &mut B,
    key: &[u8],
) -> Result<Option<T>, String> {
    state
        .read(key)
        .map(|bytes| {
            borsh::from_slice(&bytes).map_err(|_| alloc::format!("malformed state record: {key:?}"))
        })
        .transpose()
}

/// Write a canonical runtime-owned record.
pub fn write_record<T: BorshSerialize, B: StateBackend>(state: &mut B, key: &[u8], value: &T) {
    state.write(key, borsh::to_vec(value).expect("canonical runtime record"));
}

#[cfg(test)]
mod cache_tests;
