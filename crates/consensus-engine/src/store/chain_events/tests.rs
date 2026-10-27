use super::*;
use crate::test_db::{FaultDb, header};

fn store() -> ChainStore<FaultDb> {
    let mut store = ChainStore::new(FaultDb::default());
    store.commit_tip([1; 32], [1; 32], Batch::new()).unwrap();
    store.put_finalized_head([1; 32]).unwrap();
    store
        .initialize_chain_events([2; 32], [3; 32], [1; 32])
        .unwrap();
    store
}
fn publish(store: &mut ChainStore<FaultDb>, height: u64, slot: u64, parent: Hash) -> Hash {
    let header = header(height, slot, parent, [4; 32]);
    let hash = header.hash();
    let mut batch = Batch::new();
    batch.put(Column::Headers, hash, borsh::to_vec(&header).unwrap());
    store.commit_tip(hash, [1; 32], batch).unwrap();
    hash
}

#[test]
fn canonical_reorg_finality_and_restart_share_one_durable_stream() {
    let mut store = store();
    let first = publish(&mut store, 1, 1, [1; 32]);
    let second = publish(&mut store, 2, 2, first);
    let fork = publish(&mut store, 1, 3, [1; 32]);
    let reorg = store.chain_event(4).unwrap().unwrap();
    assert_eq!(reorg.previous_head.unwrap().hash, second);
    assert_eq!(reorg.head.hash, fork);
    assert_eq!(
        reorg.common_ancestor,
        Some(ChainPoint {
            hash: [1; 32],
            height: 0
        })
    );
    assert!(store.get_block_hash_by_height(2).unwrap().is_none());
    let mut batch = Batch::new();
    batch.put(Column::Finalized, pointers::FINALIZED_HEAD, fork);
    batch.put(
        Column::Finalized,
        pointers::LATEST_FINALIZED_CHUNK_ID,
        0_u64.to_be_bytes(),
    );
    store.write_observed_batch(batch, true).unwrap();
    assert_eq!(store.chain_event(5).unwrap().unwrap().finalized_chunks, 1);
    let state = store.chain_event_state().unwrap().unwrap();
    let mut reopened = ChainStore::new(store.into_db());
    reopened
        .initialize_chain_events([9; 32], [3; 32], [1; 32])
        .unwrap();
    assert_eq!(reopened.chain_event_state().unwrap().unwrap(), state);
    assert!(
        reopened
            .initialize_chain_events([9; 32], [9; 32], [1; 32])
            .is_err()
    );
    reopened.commit_tip(fork, [1; 32], Batch::new()).unwrap();
    assert_eq!(
        reopened.chain_event_state().unwrap().unwrap().next,
        state.next
    );
}

#[test]
fn failed_publication_never_advances_event_state_or_stages_a_header() {
    let mut store = store();
    let before = store.chain_event_state().unwrap().unwrap();
    store.db_mut().fail_durable_after = Some(0);
    let header = header(1, 1, [1; 32], [4; 32]);
    let hash = header.hash();
    let mut batch = Batch::new();
    batch.put(Column::Headers, hash, borsh::to_vec(&header).unwrap());
    assert!(store.commit_tip(hash, [1; 32], batch).is_err());
    assert_eq!(store.chain_event_state().unwrap().unwrap(), before);
    assert_eq!(store.get_tip().unwrap(), Some([1; 32]));
    assert!(store.get_header(&hash).unwrap().is_none());
    assert!(store.chain_event(2).unwrap().is_none());
}

#[test]
fn event_window_is_bounded_and_missing_rows_refuse_restart() {
    let mut store = store();
    let mut parent = [1; 32];
    for height in 1..=CHAIN_EVENT_WINDOW + 3 {
        parent = publish(&mut store, height, height, parent);
    }
    let state = store.chain_event_state().unwrap().unwrap();
    assert_eq!(state.next - state.oldest, CHAIN_EVENT_WINDOW);
    assert!(store.chain_event(state.oldest - 1).unwrap().is_none());
    assert_eq!(
        store
            .db()
            .iter_prefix(Column::Meta, EVENT_PREFIX)
            .unwrap()
            .len() as u64,
        CHAIN_EVENT_WINDOW
    );
    store
        .db_mut()
        .delete(Column::Meta, &event_key(state.next - 2))
        .unwrap();
    let mut reopened = ChainStore::new(store.into_db());
    assert!(
        reopened
            .initialize_chain_events([9; 32], [3; 32], [1; 32])
            .is_err()
    );
}

#[test]
fn checkpoint_jump_is_explicit_when_intermediate_ancestry_is_absent() {
    let mut store = store();
    let last = header(128, 128, [8; 32], [4; 32]);
    let hash = last.hash();
    let mut batch = Batch::new();
    batch.put(Column::Headers, hash, borsh::to_vec(&last).unwrap());
    for key in [pointers::TIP, pointers::FINALIZED_HEAD] {
        batch.put(Column::Finalized, key, hash);
    }
    batch.put(
        Column::Finalized,
        pointers::LATEST_FINALIZED_CHUNK_ID,
        127_u64.to_be_bytes(),
    );
    store.write_observed_batch(batch, true).unwrap();
    let event = store.chain_event(2).unwrap().unwrap();
    assert!(event.common_ancestor.is_none());
    assert_eq!(event.finalized_chunks, 128);
}
