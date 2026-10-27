use super::*;
use neutrin0_runtime_abi::{StateWitness, TrieNodeBytes, TrieValueBytes};
use neutrin0_trie::{Poseidon2Hasher, Trie};

fn empty_witness() -> StateWitness {
    StateWitness {
        pre_state_root: EMPTY_STATE_ROOT,
        nodes: alloc::vec![],
        values: alloc::vec![],
        witnessed_keys: alloc::vec![],
    }
}

#[test]
fn empty_witness_yields_empty_state_root() {
    let state = WitnessState::new(&empty_witness()).unwrap();
    assert_eq!(state.pre_state_root(), EMPTY_STATE_ROOT);
    assert_eq!(state.post_state_root(), EMPTY_STATE_ROOT);
}

#[test]
fn witness_state_rejects_non_empty_root_with_no_nodes() {
    let bad = StateWitness {
        pre_state_root: [9; 32],
        nodes: alloc::vec![],
        values: alloc::vec![],
        witnessed_keys: alloc::vec![],
    };
    let err = WitnessState::new(&bad).expect_err("must reject");
    assert!(matches!(err, WitnessError::PreRootMissing { .. }));
}

#[test]
fn witness_state_rejects_forged_node_hash() {
    let bad = StateWitness {
        pre_state_root: [9; 32],
        nodes: alloc::vec![TrieNodeBytes {
            hash: [9; 32],
            bytes: b"clearly not the canonical node encoding".to_vec(),
        }],
        values: alloc::vec![],
        witnessed_keys: alloc::vec![],
    };
    let err = WitnessState::new(&bad).expect_err("must reject");
    assert!(matches!(err, WitnessError::NodeHashMismatch { .. }));
}

#[test]
#[should_panic(expected = "witness missing entry for key")]
fn witness_state_panics_on_unwitnessed_read() {
    let mut state = WitnessState::new(&empty_witness()).unwrap();
    let _ = state.read(b"unknown");
}

/// Force-construct a witness directly from raw node bytes to keep
/// the test independent of the host's `LiveTrie` helper (which
/// lives behind the `host` feature).
#[test]
fn witness_state_writes_change_post_state_root() {
    // Build a trie with a single key/value via TracingState-style
    // raw construction.
    let mut trie = Trie::<Poseidon2Hasher>::new();
    trie.insert(b"k", b"v".to_vec()).unwrap();
    let pre_root = trie.root();

    let mut nodes = alloc::collections::BTreeMap::new();
    let mut values = alloc::collections::BTreeMap::new();
    trie.collect_path_nodes(b"k", &mut nodes, &mut values)
        .unwrap();

    let witness = StateWitness {
        pre_state_root: pre_root,
        nodes: nodes
            .into_iter()
            .map(|(hash, bytes)| TrieNodeBytes { hash, bytes })
            .collect(),
        values: values
            .into_iter()
            .map(|(hash, bytes)| TrieValueBytes { hash, bytes })
            .collect(),
        witnessed_keys: alloc::vec![b"k".to_vec()],
    };

    let mut owned = WitnessState::from_owned(witness.clone()).unwrap();
    let mut state = WitnessState::new(&witness).unwrap();
    assert_eq!(owned.read(b"k"), state.read(b"k"));
    owned.write(b"k", b"v2".to_vec());
    assert_eq!(state.read(b"k").as_deref(), Some(b"v".as_ref()));
    state.write(b"k", b"v2".to_vec());
    assert_eq!(state.read(b"k").as_deref(), Some(b"v2".as_ref()));
    assert_ne!(state.post_state_root(), pre_root);
    assert_eq!(owned.post_state_root(), state.post_state_root());
    let mut forged = witness;
    forged.values[0].bytes.push(0xff);
    assert!(matches!(
        WitnessState::from_owned(forged),
        Err(WitnessError::ValueHashMismatch { .. })
    ));
}

/// A witness that keeps every node but omits a read key's value still
/// authenticates the pre-state root, but cannot open its declared read.
/// Construction must reject it rather than treating the record as absent.
#[test]
fn witness_state_rejects_a_declared_read_whose_value_was_omitted() {
    let mut trie = Trie::<Poseidon2Hasher>::new();
    trie.insert(b"k", b"v".to_vec()).unwrap();
    let mut nodes = alloc::collections::BTreeMap::new();
    let mut values = alloc::collections::BTreeMap::new();
    trie.collect_path_nodes(b"k", &mut nodes, &mut values)
        .unwrap();
    let witness = StateWitness {
        pre_state_root: trie.root(),
        nodes: nodes
            .into_iter()
            .map(|(hash, bytes)| TrieNodeBytes { hash, bytes })
            .collect(),
        values: alloc::vec![],
        witnessed_keys: alloc::vec![b"k".to_vec()],
    };
    assert!(matches!(
        WitnessState::new(&witness),
        Err(WitnessError::IncompletePath { .. })
    ));
    assert!(matches!(
        WitnessState::from_owned(witness),
        Err(WitnessError::IncompletePath { .. })
    ));
}
