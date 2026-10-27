use super::*;
use crate::test_db::{FaultDb, header};
use neutrin0_consensus_types::{Block, Body};

#[test]
fn execution_locators_and_payload_pruning_commit_atomically_and_survive_restart() {
    let genesis = [1; 32];
    let mut store = ChainStore::new(FaultDb::default());
    store.commit_tip(genesis, genesis, Batch::new()).unwrap();
    let mut parent = genesis;
    let mut hashes = Vec::new();
    for height in 1..=3 {
        let byte = u8::try_from(height).unwrap();
        let body = Body {
            transactions: vec![vec![byte]],
            artifacts: neutrin0_runtime_abi::ExecutionArtifacts {
                transaction_ids: vec![(0, [byte; 32])],
                ..neutrin0_runtime_abi::ExecutionArtifacts::default()
            },
            ..Body::default()
        };
        let mut block = Block {
            header: header(height, height, parent, [byte; 32]),
            body,
        };
        block.header.receipts_root = block.body.artifacts.commitment();
        let hash = block.hash();
        store
            .commit_tip(
                hash,
                genesis,
                ChainStore::<FaultDb>::block_archive_batch(&block, None, None).unwrap(),
            )
            .unwrap();
        hashes.push(hash);
        parent = hash;
    }
    store.put_finalized_head(parent).unwrap();
    let info = RetentionInfo {
        policy: RetentionPolicy::Pruned,
        pruned_before_chunk: 1,
        first_retained_height: 3,
    };
    let mut batch = Batch::new();
    store.prune_blocks(&mut batch, info, genesis).unwrap();
    batch.put(Column::Meta, RETENTION_KEY, borsh::to_vec(&info).unwrap());
    store.db_mut().fail_batch = true;
    assert!(store.db_mut().write_batch(batch.clone()).is_err());
    assert!(store.get_body(&hashes[0]).unwrap().is_some());
    assert_eq!(
        store.execution_transaction(&[1; 32]).unwrap(),
        Some((hashes[0], 0))
    );
    store.db_mut().fail_batch = false;
    store.db_mut().write_batch(batch).unwrap();
    let reopened = ChainStore::new(store.db().clone());
    assert_eq!(reopened.retention_info().unwrap(), info);
    assert!(reopened.get_body(&hashes[0]).unwrap().is_none());
    assert!(reopened.get_body(&hashes[1]).unwrap().is_none());
    assert_eq!(reopened.execution_transaction(&[1; 32]).unwrap(), None);
    assert_eq!(reopened.execution_transaction(&[2; 32]).unwrap(), None);
    assert_eq!(
        reopened.execution_transaction(&[3; 32]).unwrap(),
        Some((hashes[2], 0))
    );
    assert!(reopened.get_header(&hashes[1]).unwrap().is_some());
}
