use super::*;
use alloc::vec;

#[derive(Default)]
struct Store {
    values: BTreeMap<Vec<u8>, Vec<u8>>,
    code_reads: usize,
    code_writes: usize,
}

impl StateBackend for Store {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.code_reads += usize::from(key.starts_with(b"evm:code:"));
        self.values.get(key).cloned()
    }
    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        self.code_writes += usize::from(key.starts_with(b"evm:code:"));
        self.values.insert(key.to_vec(), value);
    }
    fn delete(&mut self, key: &[u8]) {
        self.values.remove(key);
    }
    fn pre_state_root(&self) -> [u8; 32] {
        [0; 32]
    }
    fn post_state_root(&self) -> [u8; 32] {
        [0; 32]
    }
}

#[test]
fn bytecode_authentication_is_shared_without_rewriting_or_sharing_journals() {
    let bytes = vec![0x60, 0x01, 0x00];
    let hash = keccak256(&bytes);
    let address = Address::from([0x12; 20]);
    let mut store = Store::default();
    store.values.insert(code_key(hash), bytes.clone());
    let mut cache = VerifiedBytecodeCache::default();
    for _ in 0..2 {
        let mut db = StateDb::with_code_cache(&mut store, 1, &mut cache);
        assert!(db.system_slots.is_empty());
        assert!(db.system_records.is_empty());
        let code = db.code_by_hash(hash).unwrap();
        assert_eq!(code.original_byte_slice(), bytes);
        let mut account = Account::new_not_existing(revm::state::TransactionId::ZERO);
        account.info = AccountInfo {
            balance: U256::from(1),
            nonce: 1,
            code_hash: hash,
            code: Some(code),
            ..AccountInfo::default()
        };
        account.mark_touch();
        let mut changes = AddressMap::default();
        changes.insert(address, account);
        db.commit(changes);
    }
    assert_eq!(store.code_reads, 1);
    assert_eq!(store.code_writes, 0);
    assert_eq!(
        load_account(&mut store, address)
            .unwrap()
            .unwrap()
            .code_hash,
        hash.0
    );
}

#[test]
fn forged_bytecode_never_enters_the_shared_cache() {
    let hash = keccak256([0x00]);
    let mut store = Store::default();
    store.values.insert(code_key(hash), vec![0x01]);
    let mut cache = VerifiedBytecodeCache::default();
    for _ in 0..2 {
        assert_eq!(
            StateDb::with_code_cache(&mut store, 1, &mut cache).code_by_hash(hash),
            Err(StateError("bytecode hash mismatch"))
        );
    }
    assert!(cache.entries.is_empty());
    assert_eq!(store.code_reads, 2);
}
