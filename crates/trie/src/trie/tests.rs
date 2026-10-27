use super::*;
use crate::bits::BitPath;
use crate::error::TrieError;
use crate::hasher::Blake3Hasher;
use crate::node::Node;
use crate::proof::{ProofError, ProofOutcome, ProofStep, ProofTerminal};
use alloc::vec;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

// The generic trie corpus uses `Blake3Hasher`. The default
// `Poseidon2Hasher` trie is exercised by downstream crates
// (`runtime-core`, `runtime-host`, every node integration test); the hash
// function is plug-in, so a parallel Poseidon2 corpus here adds no signal.
type TestTrie = Trie<Blake3Hasher>;

fn value(byte: u8) -> Vec<u8> {
    vec![byte; usize::from(byte % 7) + 1]
}

fn insert_many(trie: &mut TestTrie, pairs: &[(&[u8], &[u8])]) {
    for (key, value) in pairs {
        trie.insert(key, value.to_vec()).expect("insert succeeds");
    }
}

#[test]
fn persisted_lookup_reads_exactly_what_the_trie_holds() {
    let mut trie = TestTrie::new();
    let keys: Vec<Vec<u8>> = (0_u8..40)
        .map(|byte| vec![byte; usize::from(byte % 5) + 1])
        .collect();
    for (index, key) in keys.iter().enumerate() {
        trie.insert(key, value(u8::try_from(index).unwrap()))
            .unwrap();
    }
    let root = trie.root();
    let lookup = |trie: &TestTrie, key: &[u8]| {
        lookup_persisted(
            root,
            key,
            |hash| trie.nodes.get(hash).cloned(),
            |hash| trie.values.get(hash).cloned(),
        )
    };
    for key in &keys {
        assert_eq!(lookup(&trie, key), trie.get(key));
    }
    for absent in [&b""[..], b"missing", &[0_u8; 9], &[39_u8; 7]] {
        assert_eq!(trie.get(absent).unwrap(), None);
        assert_eq!(lookup(&trie, absent), Ok(None));
    }
    assert_eq!(
        lookup_persisted(ZERO_HASH, b"any", |_| None, |_| None),
        Ok(None)
    );
    assert_eq!(
        lookup_persisted(root, &keys[0], |_| None, |_| None),
        Err(TrieError::MissingRetainedEntry)
    );
}

#[test]
fn new_trie_has_empty_root() {
    let trie = TestTrie::new();
    assert_eq!(trie.root(), ZERO_HASH);
    assert_eq!(trie.node_count(), 0);
    assert_eq!(trie.value_count(), 0);
    assert_eq!(trie.get(b"missing").unwrap(), None);
}

#[cfg(feature = "store")]
#[derive(Debug, Default)]
struct MapSource {
    nodes: BTreeMap<Hash, Vec<u8>>,
    values: BTreeMap<Hash, Vec<u8>>,
}

#[cfg(feature = "store")]
impl NodeSource for MapSource {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.nodes.get(hash).cloned()
    }
    fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.values.get(hash).cloned()
    }
}

#[cfg(feature = "store")]
#[test]
fn a_sourced_trie_reads_through_and_holds_only_what_it_produced() {
    let mut built = TestTrie::new();
    for byte in 0_u8..32 {
        built.insert(&[byte], value(byte)).unwrap();
    }
    let source = MapSource {
        nodes: built.drain_pending_nodes().into_iter().collect(),
        values: built.drain_pending_values().into_iter().collect(),
    };
    let mut sourced = TestTrie::with_source(built.root(), Arc::new(source));
    assert_eq!(sourced.node_count(), 0);
    assert_eq!(sourced.get(&[7]).unwrap(), Some(value(7)));
    assert!(sourced.node_bytes(&built.root()).unwrap().is_some());
    assert!(sourced.overlay_node(&built.root()).is_none());
    sourced.insert(&[200], value(200)).unwrap();
    built.insert(&[200], value(200)).unwrap();
    assert_eq!(sourced.root(), built.root());
    // Only the copied path is new; the rest still comes from the source.
    assert!(sourced.node_count() < 16);
    assert!(sourced.overlay_node(&sourced.root()).is_some());
    assert_eq!(sourced.remove(&[3]).unwrap(), Some(value(3)));
}

#[cfg(feature = "store")]
#[test]
fn witness_collection_refuses_source_bytes_that_miss_their_hash() {
    let mut built = TestTrie::new();
    for byte in 0_u8..32 {
        built.insert(&[byte], value(byte)).unwrap();
    }
    // Only reachable entries, so each corruption below is one a read meets.
    built.retain_roots(&[]).unwrap();
    let nodes: BTreeMap<_, _> = built.drain_pending_nodes().into_iter().collect();
    let values: BTreeMap<_, _> = built.drain_pending_values().into_iter().collect();
    let collect = |nodes: &BTreeMap<Hash, Vec<u8>>, values: &BTreeMap<Hash, Vec<u8>>| {
        let source = MapSource {
            nodes: nodes.clone(),
            values: values.clone(),
        };
        let sourced = TestTrie::with_source(built.root(), Arc::new(source));
        let (mut out_nodes, mut out_values) = (BTreeMap::new(), BTreeMap::new());
        sourced
            .collect_path_nodes(&[7], &mut out_nodes, &mut out_values)
            .map(|()| sourced.detached().map(|_| ()))
    };
    assert_eq!(collect(&nodes, &values), Ok(Ok(())));
    // Witnesses and detached copies take source bytes as they are, so
    // a corrupt entry fails the build rather than the Guest's check.
    let mut corrupt_value = values.clone();
    corrupt_value.insert(Blake3Hasher::hash_value(&value(7)), value(8));
    assert_eq!(
        collect(&nodes, &corrupt_value),
        Err(TrieError::RetainedHashMismatch)
    );
    for (hash, bytes) in &nodes {
        let other = nodes.values().find(|other| *other != bytes).unwrap();
        let mut corrupt_node = nodes.clone();
        corrupt_node.insert(*hash, other.clone());
        let result = collect(&corrupt_node, &values);
        assert!(
            matches!(
                result,
                Err(TrieError::RetainedHashMismatch) | Ok(Err(TrieError::RetainedHashMismatch))
            ),
            "{result:?}"
        );
    }
}

#[test]
fn pruning_preserves_current_and_leased_roots_then_reclaims_released_state() {
    let mut trie = TestTrie::new();
    trie.insert(b"account", b"old".to_vec()).unwrap();
    let old_root = trie.root();
    trie.insert(b"account", b"middle".to_vec()).unwrap();
    let middle_root = trie.root();
    trie.insert(b"account", b"current".to_vec()).unwrap();
    let current_root = trie.root();
    trie.retain_roots(&[old_root]).unwrap();
    assert_eq!(trie.root(), current_root);
    assert_eq!(trie.get(b"account").unwrap(), Some(b"current".to_vec()));
    assert!(trie.node_bytes(&old_root).unwrap().is_some());
    assert!(trie.node_bytes(&middle_root).unwrap().is_none());
    assert_eq!(trie.node_count(), 2);
    assert_eq!(trie.value_count(), 2);
    assert_eq!(trie.pending_nodes.len(), 2);
    assert_eq!(trie.pending_values.len(), 2);
    let nodes = trie.drain_pending_nodes();
    let values = trie.drain_pending_values();
    let restored = TestTrie::from_persisted(old_root, nodes, values);
    assert_eq!(restored.get(b"account").unwrap(), Some(b"old".to_vec()));
    trie.retain_roots(&[]).unwrap();
    assert!(trie.node_bytes(&old_root).unwrap().is_none());
    assert_eq!(trie.node_count(), 1);
    assert_eq!(trie.value_count(), 1);
}

#[test]
fn pruning_checks_reachable_state_before_deleting_anything() {
    let mut trie = TestTrie::new();
    trie.insert(b"account", b"old".to_vec()).unwrap();
    trie.insert(b"account", b"current".to_vec()).unwrap();
    let original = trie.clone();
    assert_eq!(
        trie.retain_roots(&[[99; 32]]),
        Err(TrieError::MissingRetainedEntry)
    );
    assert_eq!(trie.nodes, original.nodes);
    assert_eq!(trie.values, original.values);
    let value_hash = <crate::Blake3Hasher as Hasher>::hash_value(b"current");
    trie.values.insert(value_hash, b"corrupt".to_vec());
    let corrupt_values = trie.values.clone();
    assert_eq!(trie.retain_roots(&[]), Err(TrieError::RetainedHashMismatch));
    assert_eq!(trie.nodes, original.nodes);
    assert_eq!(trie.values, corrupt_values);
    trie.values.remove(&value_hash);
    assert_eq!(trie.retain_roots(&[]), Err(TrieError::MissingRetainedEntry));
    assert_eq!(trie.nodes, original.nodes);
}

#[test]
fn insert_and_get_single_value() {
    let mut trie = TestTrie::new();
    trie.insert(b"account:alice", b"100".to_vec())
        .expect("insert");
    assert_eq!(trie.get(b"account:alice").unwrap(), Some(b"100".to_vec()));
    assert_eq!(trie.get(b"account:bob").unwrap(), None);
    assert_ne!(trie.root(), ZERO_HASH);
}

#[test]
fn keys_returns_raw_keys_in_lexicographic_order() {
    let mut trie = TestTrie::new();
    trie.insert(b"gamma", b"3".to_vec()).expect("insert");
    trie.insert(b"alpha", b"1".to_vec()).expect("insert");
    trie.insert(b"alphabet", b"2".to_vec()).expect("insert");

    assert_eq!(
        trie.keys().unwrap(),
        vec![b"alpha".to_vec(), b"alphabet".to_vec(), b"gamma".to_vec()]
    );
}

#[test]
fn overwrite_changes_value_and_root() {
    let mut trie = TestTrie::new();
    trie.insert(b"k", b"v1".to_vec()).expect("insert");
    let first_root = trie.root();
    trie.insert(b"k", b"v2".to_vec()).expect("overwrite");
    assert_eq!(trie.get(b"k").unwrap(), Some(b"v2".to_vec()));
    assert_ne!(trie.root(), first_root);
}

#[test]
fn insertion_order_does_not_change_root() {
    let pairs: [(&[u8], &[u8]); 5] = [
        (b"alpha", b"1"),
        (b"beta", b"2"),
        (b"gamma", b"3"),
        (b"delta", b"4"),
        (b"epsilon", b"5"),
    ];

    let mut forward = TestTrie::new();
    insert_many(&mut forward, &pairs);

    let mut reverse = TestTrie::new();
    for (key, value) in pairs.iter().rev() {
        reverse.insert(key, value.to_vec()).expect("insert");
    }

    assert_eq!(forward.root(), reverse.root());
    for (key, value) in pairs {
        assert_eq!(forward.get(key).unwrap(), Some(value.to_vec()));
        assert_eq!(reverse.get(key).unwrap(), Some(value.to_vec()));
    }
}

#[test]
fn prefix_like_raw_keys_are_supported() {
    let mut trie = TestTrie::new();
    trie.insert(b"a", b"short".to_vec()).expect("insert a");
    trie.insert(b"ab", b"longer".to_vec()).expect("insert ab");
    trie.insert(b"", b"empty".to_vec()).expect("insert empty");

    assert_eq!(trie.get(b"a").unwrap(), Some(b"short".to_vec()));
    assert_eq!(trie.get(b"ab").unwrap(), Some(b"longer".to_vec()));
    assert_eq!(trie.get(b"").unwrap(), Some(b"empty".to_vec()));
}

#[test]
fn removing_missing_key_keeps_root() {
    let mut trie = TestTrie::new();
    trie.insert(b"present", b"value".to_vec()).expect("insert");
    let root = trie.root();
    assert_eq!(trie.remove(b"absent").unwrap(), None);
    assert_eq!(trie.root(), root);
    assert_eq!(trie.get(b"present").unwrap(), Some(b"value".to_vec()));
}

#[test]
fn removing_last_key_restores_empty_root() {
    let mut trie = TestTrie::new();
    trie.insert(b"only", b"value".to_vec()).expect("insert");
    assert_eq!(trie.remove(b"only").unwrap(), Some(b"value".to_vec()));
    assert_eq!(trie.root(), ZERO_HASH);
    assert_eq!(trie.get(b"only").unwrap(), None);
}

#[test]
fn removal_collapses_back_to_same_single_key_root() {
    let mut single = TestTrie::new();
    single.insert(b"left", b"1".to_vec()).expect("insert");

    let mut pair = single.clone();
    pair.insert(b"right", b"2".to_vec()).expect("insert");
    assert_ne!(pair.root(), single.root());
    assert_eq!(pair.remove(b"right").unwrap(), Some(b"2".to_vec()));
    assert_eq!(pair.root(), single.root());
    assert_eq!(pair.get(b"left").unwrap(), Some(b"1".to_vec()));
}

#[test]
fn inclusion_proof_verifies() {
    let mut trie = TestTrie::new();
    insert_many(
        &mut trie,
        &[(b"alice", b"100"), (b"bob", b"50"), (b"carol", b"75")],
    );

    let proof = trie.prove(b"bob").unwrap();
    let root = trie.root();
    assert_eq!(
        proof.verify::<Blake3Hasher>(&root, b"bob").expect("verify"),
        ProofOutcome::Included {
            value_hash: Blake3Hasher::hash_value(b"50")
        }
    );
    proof
        .verify_inclusion::<Blake3Hasher>(&root, b"bob", b"50")
        .expect("inclusion");
}

#[test]
fn inclusion_proof_rejects_wrong_value() {
    let mut trie = TestTrie::new();
    trie.insert(b"bob", b"50".to_vec()).expect("insert");
    let proof = trie.prove(b"bob").unwrap();
    assert_eq!(
        proof.verify_inclusion::<Blake3Hasher>(&trie.root(), b"bob", b"51"),
        Err(ProofError::ValueHashMismatch)
    );
}

#[test]
fn exclusion_proof_for_empty_trie_verifies() {
    let trie = TestTrie::new();
    let proof = trie.prove(b"anything").unwrap();
    assert_eq!(proof.terminal, ProofTerminal::Empty);
    proof
        .verify_exclusion::<Blake3Hasher>(&trie.root(), b"anything")
        .expect("exclusion");
}

#[test]
fn exclusion_proof_for_empty_subtree_verifies() {
    let mut trie = TestTrie::new();
    trie.insert(b"alice", b"100".to_vec()).expect("insert");
    trie.insert(b"bob", b"50".to_vec()).expect("insert");
    let proof = trie.prove(b"carol").unwrap();
    proof
        .verify_exclusion::<Blake3Hasher>(&trie.root(), b"carol")
        .expect("exclusion");
}

#[test]
fn exclusion_proof_for_other_leaf_verifies() {
    let mut trie = TestTrie::new();
    trie.insert(b"alice", b"100".to_vec()).expect("insert");
    let proof = trie.prove(b"bob").unwrap();
    assert!(matches!(proof.terminal, ProofTerminal::Leaf { .. }));
    proof
        .verify_exclusion::<Blake3Hasher>(&trie.root(), b"bob")
        .expect("exclusion");
}

#[test]
fn divergent_extension_exclusion_verifies() {
    let mut trie = TestTrie::new();
    trie.insert(b"aaaaaaaa", b"1".to_vec()).expect("insert");
    trie.insert(b"aaaaaaab", b"2".to_vec()).expect("insert");
    let proof = trie.prove(b"bbbbbbbb").unwrap();
    assert!(matches!(
        proof.terminal,
        ProofTerminal::DivergentExtension { .. }
    ));
    proof
        .verify_exclusion::<Blake3Hasher>(&trie.root(), b"bbbbbbbb")
        .expect("exclusion");
}

#[test]
fn proof_rejects_wrong_root() {
    let mut trie = TestTrie::new();
    trie.insert(b"key", b"value".to_vec()).expect("insert");
    let proof = trie.prove(b"key").unwrap();
    let mut wrong_root = trie.root();
    wrong_root[0] ^= 0x01;
    assert_eq!(
        proof.verify_inclusion::<Blake3Hasher>(&wrong_root, b"key", b"value"),
        Err(ProofError::RootMismatch)
    );
}

#[test]
fn proof_rejects_tampered_branch_direction() {
    let mut trie = TestTrie::new();
    trie.insert(b"alpha", b"1".to_vec()).expect("insert");
    trie.insert(b"omega", b"2".to_vec()).expect("insert");
    let mut proof = trie.prove(b"alpha").unwrap();
    let step = proof
        .steps
        .iter_mut()
        .find(|step| matches!(step, ProofStep::Branch { .. }))
        .expect("at least one branch step");
    if let ProofStep::Branch {
        descended_right, ..
    } = step
    {
        *descended_right = !*descended_right;
    }
    assert_eq!(
        proof.verify::<Blake3Hasher>(&trie.root(), b"alpha"),
        Err(ProofError::BranchBitMismatch)
    );
}

#[test]
fn drain_pending_returns_new_entries_and_then_empties() {
    let mut trie = TestTrie::new();
    assert_eq!(trie.drain_pending_nodes(), [] as [(Hash, Vec<u8>); 0]);
    assert_eq!(trie.drain_pending_values(), [] as [(Hash, Vec<u8>); 0]);

    trie.insert(b"a", b"1".to_vec()).expect("insert");
    let nodes = trie.drain_pending_nodes();
    let values = trie.drain_pending_values();
    assert!(!nodes.is_empty(), "insert must produce at least one node");
    assert!(!values.is_empty(), "insert must produce at least one value");
    // Second drain returns nothing because no new writes happened.
    assert_eq!(trie.drain_pending_nodes(), [] as [(Hash, Vec<u8>); 0]);
    assert_eq!(trie.drain_pending_values(), [] as [(Hash, Vec<u8>); 0]);

    // Re-inserting an identical value-byte does not record a new
    // value, since the value hash already lives in the value store.
    trie.insert(b"a", b"1".to_vec()).expect("re-insert");
    assert!(
        trie.drain_pending_values().is_empty(),
        "duplicate value should not be queued for persistence"
    );
}

#[test]
fn from_persisted_roundtrips_reads_and_proofs() {
    let mut original = TestTrie::new();
    insert_many(
        &mut original,
        &[(b"alice", b"100"), (b"bob", b"50"), (b"carol", b"75")],
    );
    let root = original.root();
    let nodes = original.drain_pending_nodes();
    let values = original.drain_pending_values();

    let reopened = TestTrie::from_persisted(root, nodes, values);
    assert_eq!(reopened.root(), root);
    assert_eq!(reopened.get(b"alice").unwrap(), Some(b"100".to_vec()));
    assert_eq!(reopened.get(b"bob").unwrap(), Some(b"50".to_vec()));
    assert_eq!(reopened.get(b"carol").unwrap(), Some(b"75".to_vec()));
    reopened
        .prove(b"bob")
        .unwrap()
        .verify_inclusion::<Blake3Hasher>(&root, b"bob", b"50")
        .expect("inclusion in reopened trie");
}

#[test]
fn a_present_key_whose_value_is_missing_never_reads_as_absent() {
    let mut original = TestTrie::new();
    insert_many(&mut original, &[(b"alice", b"100"), (b"bob", b"50")]);
    let root = original.root();
    let nodes = original.drain_pending_nodes();
    // Every node on the path is present; only the leaf values are not.
    let partial = TestTrie::from_persisted(root, nodes, []);
    assert_eq!(partial.get(b"bob"), Err(TrieError::MissingRetainedEntry));
    // A missing node on the path is reported the same way, not as absence.
    let rootless = TestTrie::from_persisted(root, [], []);
    assert_eq!(rootless.get(b"bob"), Err(TrieError::MissingRetainedEntry));
    assert_eq!(rootless.prove(b"bob"), Err(TrieError::MissingRetainedEntry));
    assert_eq!(rootless.keys(), Err(TrieError::MissingRetainedEntry));
}

#[test]
fn random_insert_get_remove_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5452_4945);
    let mut trie = TestTrie::new();
    let mut pairs = Vec::new();

    for index in 0..64_u8 {
        let mut key = [0_u8; 16];
        rng.fill_bytes(&mut key);
        let v = value(index);
        trie.insert(&key, v.clone()).expect("insert random key");
        pairs.push((key, v));
    }

    for (key, v) in &pairs {
        assert_eq!(trie.get(key).unwrap(), Some(v.clone()));
        trie.prove(key)
            .unwrap()
            .verify_inclusion::<Blake3Hasher>(&trie.root(), key, v)
            .expect("random inclusion proof");
    }

    for (key, v) in pairs.iter().take(32) {
        assert_eq!(trie.remove(key).unwrap(), Some(v.clone()));
        assert_eq!(trie.get(key).unwrap(), None);
        trie.prove(key)
            .unwrap()
            .verify_exclusion::<Blake3Hasher>(&trie.root(), key)
            .expect("random exclusion proof");
    }
}

/// Root of the canonical trie holding exactly `leaves`, built from scratch:
/// one key is a leaf, keys sharing a nonempty prefix sit under an extension,
/// and otherwise the first bit splits them under a branch.
fn canonical_subtree(leaves: &[(BitPath, Hash)]) -> Hash {
    let node = match leaves {
        [] => return ZERO_HASH,
        [(key_suffix, value_hash)] => Node::Leaf {
            key_suffix: key_suffix.clone(),
            value_hash: *value_hash,
        },
        [(first, _), rest @ ..] => {
            let common = rest
                .iter()
                .map(|(path, _)| first.common_prefix_len(path))
                .min()
                .unwrap();
            if common > 0 {
                let children: Vec<_> = leaves
                    .iter()
                    .map(|(path, value_hash)| (path.suffix(common), *value_hash))
                    .collect();
                Node::Extension {
                    prefix: first.prefix(common),
                    child: canonical_subtree(&children),
                }
            } else {
                let (mut left, mut right) = (Vec::new(), Vec::new());
                for (path, value_hash) in leaves {
                    let side = if path.bit(0) { &mut right } else { &mut left };
                    side.push((path.suffix(1), *value_hash));
                }
                Node::Branch {
                    left: canonical_subtree(&left),
                    right: canonical_subtree(&right),
                }
            }
        }
    };
    Blake3Hasher::hash_node(&node.encode())
}

fn canonical_root(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash {
    let leaves: Vec<_> = entries
        .iter()
        .map(|(key, value)| (BitPath::for_key(key), Blake3Hasher::hash_value(value)))
        .collect();
    canonical_subtree(&leaves)
}

#[test]
fn incremental_roots_match_a_from_scratch_canonical_build() {
    fn below(rng: &mut ChaCha20Rng, bound: u32) -> usize {
        usize::try_from(rng.next_u32() % bound).unwrap()
    }
    let alphabet = [0x00, 0x01, 0x7F, 0x80, 0xFF];
    let mut rng = ChaCha20Rng::seed_from_u64(0x4F46_4653);
    let mut keys = Vec::new();
    for _ in 0..48 {
        let len = below(&mut rng, 6);
        let key: Vec<u8> = (0..len).map(|_| alphabet[below(&mut rng, 5)]).collect();
        keys.push(key);
    }
    let mut trie = TestTrie::new();
    let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for step in 0..400_usize {
        let key = &keys[below(&mut rng, 48)];
        if below(&mut rng, 3) == 0 {
            assert_eq!(
                trie.remove(key).unwrap(),
                entries.remove(key),
                "step {step}"
            );
        } else {
            let value = vec![u8::try_from(step % 251).unwrap(); 1 + step % 5];
            trie.insert(key, value.clone()).expect("insert");
            entries.insert(key.clone(), value);
        }
        assert_eq!(trie.root(), canonical_root(&entries), "step {step}");
    }
    for (key, value) in &entries {
        assert_eq!(trie.get(key).unwrap().as_ref(), Some(value));
    }
}

#[test]
fn collect_path_nodes_yields_a_partial_subtree_that_round_trips() {
    // Populate a small trie and verify that the nodes collected for
    // one key are enough to reconstruct a partial trie supporting
    // both read and write on that key.
    let mut trie: Trie<Blake3Hasher> = Trie::new();
    for (k, v) in [
        (b"alpha".as_ref(), b"1".to_vec()),
        (b"beta".as_ref(), b"2".to_vec()),
        (b"gamma".as_ref(), b"3".to_vec()),
        (b"delta".as_ref(), b"4".to_vec()),
    ] {
        trie.insert(k, v).unwrap();
    }
    let root = trie.root();

    let mut nodes = BTreeMap::new();
    let mut values = BTreeMap::new();
    // Touch alpha (read) and a fresh key (write). The witness must
    // cover both paths.
    trie.collect_path_nodes(b"alpha", &mut nodes, &mut values)
        .unwrap();
    trie.collect_path_nodes(b"epsilon", &mut nodes, &mut values)
        .unwrap();

    let partial = Trie::<Blake3Hasher>::from_persisted(
        root,
        nodes.iter().map(|(h, b)| (*h, b.clone())),
        values.iter().map(|(h, b)| (*h, b.clone())),
    );
    // Read of a witnessed key returns the same value.
    assert_eq!(
        partial.get(b"alpha").unwrap().as_deref(),
        Some(b"1".as_ref())
    );
    // Insert at the fresh key bumps the root.
    let mut writable = partial;
    writable.insert(b"epsilon", b"5".to_vec()).unwrap();
    let mut reference = trie;
    reference.insert(b"epsilon", b"5".to_vec()).unwrap();
    assert_eq!(writable.root(), reference.root());
}

#[test]
fn collect_path_nodes_on_empty_trie_yields_nothing() {
    let trie: Trie<Blake3Hasher> = Trie::new();
    let mut nodes = BTreeMap::new();
    let mut values = BTreeMap::new();
    trie.collect_path_nodes(b"alpha", &mut nodes, &mut values)
        .unwrap();
    assert!(nodes.is_empty());
    assert!(values.is_empty());
}

#[test]
fn collect_path_nodes_includes_branch_siblings_so_remove_round_trips() {
    // `Trie::remove` calls `absorb_into_parent` when a branch loses one
    // child to `ZERO_HASH`; that path fetches the surviving sibling's node
    // bytes, so a witness without the sibling would fail the fetch.
    //
    // Setup a trie with `left` + `right` keys whose paths diverge
    // at a Branch close to the root, take a witness covering only
    // `left`, reconstruct a partial trie, and remove `left`. The
    // removal must complete because the sibling `right` was
    // included in the witness; the post-remove root must equal
    // the root of a trie that only ever contained `right`.
    let mut full: Trie<Blake3Hasher> = Trie::new();
    full.insert(b"left-key", b"L".to_vec()).unwrap();
    full.insert(b"right-key", b"R".to_vec()).unwrap();
    let root_full = full.root();

    // Witness covering only the left key (the one we'll remove).
    let mut nodes = BTreeMap::new();
    let mut values = BTreeMap::new();
    full.collect_path_nodes(b"left-key", &mut nodes, &mut values)
        .unwrap();

    let mut partial = Trie::<Blake3Hasher>::from_persisted(
        root_full,
        nodes.iter().map(|(h, b)| (*h, b.clone())),
        values.iter().map(|(h, b)| (*h, b.clone())),
    );
    // Sanity: partial trie can read `left-key`.
    assert_eq!(
        partial.get(b"left-key").unwrap().as_deref(),
        Some(b"L".as_ref())
    );

    // Removing `left-key` must succeed and trigger sibling absorb.
    let removed = partial.remove(b"left-key").unwrap();
    assert_eq!(removed.as_deref(), Some(b"L".as_ref()));

    // Post-remove root equals a trie that only ever held `right-key`.
    let mut reference: Trie<Blake3Hasher> = Trie::new();
    reference.insert(b"right-key", b"R".to_vec()).unwrap();
    assert_eq!(partial.root(), reference.root());
}

#[test]
fn collect_path_nodes_includes_siblings_along_a_deep_path() {
    // Multiple branches between the root and the target should
    // each contribute a sibling to the witness. Build a deeper
    // trie and remove a leaf; the partial trie must reach
    // `ZERO_HASH` when its only inhabitant is the target.
    let mut full: Trie<Blake3Hasher> = Trie::new();
    let pairs: [(&[u8], &[u8]); 5] = [
        (b"alpha", b"1"),
        (b"beta", b"2"),
        (b"gamma", b"3"),
        (b"delta", b"4"),
        (b"epsilon", b"5"),
    ];
    for (k, v) in pairs {
        full.insert(k, v.to_vec()).unwrap();
    }
    let root_full = full.root();

    // Witness for every key — this is what the host's
    // TracingState would assemble if every key were touched.
    let mut nodes = BTreeMap::new();
    let mut values = BTreeMap::new();
    for (k, _) in pairs {
        full.collect_path_nodes(k, &mut nodes, &mut values).unwrap();
    }

    let mut partial = Trie::<Blake3Hasher>::from_persisted(
        root_full,
        nodes.iter().map(|(h, b)| (*h, b.clone())),
        values.iter().map(|(h, b)| (*h, b.clone())),
    );

    // Remove every key one at a time. None of the removes should
    // panic; the final root is the empty-trie root.
    for (k, expected) in pairs {
        let got = partial.remove(k).unwrap();
        assert_eq!(
            got.as_deref(),
            Some(expected),
            "removing {k:?} must return its stored value",
        );
    }
    assert_eq!(partial.root(), ZERO_HASH);
}
