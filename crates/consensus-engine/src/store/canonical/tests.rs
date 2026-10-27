use super::*;
use crate::test_db::{FaultDb, header};
use neutrin0_storage::MemoryDatabase;

#[test]
fn archive_reorg_shorter_reorg_and_restart_share_one_index() {
    let genesis = [9; 32];
    let mut store = ChainStore::new(MemoryDatabase::new());
    store.commit_tip(genesis, genesis, Batch::new()).unwrap();
    let first = store.put_header(&header(1, 1, genesis, [0; 32])).unwrap();
    let second = store.put_header(&header(2, 2, first, [0; 32])).unwrap();
    let third = store.put_header(&header(3, 3, second, [0; 32])).unwrap();
    store.commit_tip(third, genesis, Batch::new()).unwrap();
    let sibling = store.put_header(&header(2, 4, first, [1; 32])).unwrap();
    assert_eq!(
        store.get_header_by_height(2).unwrap().unwrap().hash(),
        second
    );
    let descendant = store.put_header(&header(3, 5, sibling, [1; 32])).unwrap();
    store.commit_tip(descendant, genesis, Batch::new()).unwrap();
    assert_eq!(store.get_block_hash_by_height(1).unwrap(), Some(first));
    assert_eq!(store.get_block_hash_by_height(2).unwrap(), Some(sibling));
    assert_eq!(store.get_block_hash_by_height(3).unwrap(), Some(descendant));
    store.commit_tip(first, genesis, Batch::new()).unwrap();
    assert_eq!(store.get_block_hash_by_height(2).unwrap(), None);
    assert_eq!(store.get_block_hash_by_height(3).unwrap(), None);
    let mut reopened = ChainStore::new(store.db().clone());
    reopened.validate_canonical_index(genesis).unwrap();
    reopened.commit_tip(genesis, genesis, Batch::new()).unwrap();
    assert_eq!(reopened.get_block_hash_by_height(1).unwrap(), None);
    reopened.validate_canonical_index(genesis).unwrap();
}

#[test]
fn failed_batch_preserves_tip_index_and_state_writes() {
    let genesis = [9; 32];
    let mut store = ChainStore::new(FaultDb::default());
    store.commit_tip(genesis, genesis, Batch::new()).unwrap();
    let first = store.put_header(&header(1, 1, genesis, [0; 32])).unwrap();
    let mut batch = Batch::new();
    batch.put(Column::StateValues, [1; 32], vec![42]);
    store.db_mut().fail_batch = true;
    assert!(matches!(
        store.commit_tip(first, genesis, batch),
        Err(StoreError::Database(_))
    ));
    assert_eq!(store.get_tip().unwrap(), Some(genesis));
    assert_eq!(store.get_block_hash_by_height(1).unwrap(), None);
    assert_eq!(store.db().get(Column::StateValues, &[1; 32]).unwrap(), None);
    store.validate_canonical_index(genesis).unwrap();
}

#[test]
fn index_corruption_and_invalid_ancestry_are_rejected() {
    let genesis = [9; 32];
    let mut store = ChainStore::new(MemoryDatabase::new());
    store.commit_tip(genesis, genesis, Batch::new()).unwrap();
    let first = store.put_header(&header(1, 1, genesis, [0; 32])).unwrap();
    let gap = store.put_header(&header(3, 3, first, [0; 32])).unwrap();
    assert!(matches!(
        store.commit_tip(gap, genesis, Batch::new()),
        Err(StoreError::Corrupt(_))
    ));
    let foreign = store.put_header(&header(1, 2, [88; 32], [0; 32])).unwrap();
    assert!(matches!(
        store.commit_tip(foreign, genesis, Batch::new()),
        Err(StoreError::Corrupt(_))
    ));
    store
        .db_mut()
        .put(Column::HeaderByHeight, &keys::height_key(0), &[1])
        .unwrap();
    assert!(matches!(
        store.validate_canonical_index(genesis),
        Err(StoreError::Corrupt(_))
    ));
}
