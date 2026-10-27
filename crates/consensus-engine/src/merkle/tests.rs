use super::*;

/// A committed test leaf under its own tag.
#[derive(borsh::BorshSerialize)]
struct Leaf(Vec<u8>);

impl neutrin0_consensus_types::hashing::Committed for Leaf {
    const COMMITMENT_TAG: neutrin0_primitives::DomainTag = *b"TEST_MERKLE_LEAF";
}

fn h(byte: u8) -> Hash {
    [byte; 32]
}

#[test]
fn empty_root_is_zero() {
    assert_eq!(merkle_root::<Leaf>(&[]), EMPTY_MERKLE_ROOT);
    assert_eq!(merkle_root_of_hashes(&[]), EMPTY_MERKLE_ROOT);
}

#[test]
fn single_leaf_root_is_that_leaf() {
    let leaf = h(7);
    assert_eq!(merkle_root_of_hashes(&[leaf]), leaf);
}

#[test]
fn two_leaves_hash_pairwise() {
    let a = h(1);
    let b = h(2);
    let mut concat = [0_u8; 64];
    concat[..32].copy_from_slice(&a);
    concat[32..].copy_from_slice(&b);
    let expected = blake3_256(&concat);
    assert_eq!(merkle_root_of_hashes(&[a, b]), expected);
}

#[test]
fn odd_leaf_is_promoted_to_next_level() {
    let a = h(1);
    let b = h(2);
    let c = h(3);
    let ab = merkle_root_of_hashes(&[a, b]);
    let abc = merkle_root_of_hashes(&[a, b, c]);
    // Level 1 produces [hash(a||b), c]; level 2 hashes those two.
    let mut concat = [0_u8; 64];
    concat[..32].copy_from_slice(&ab);
    concat[32..].copy_from_slice(&c);
    assert_eq!(abc, blake3_256(&concat));
}

#[test]
fn merkle_root_is_order_sensitive() {
    let r1 = merkle_root_of_hashes(&[h(1), h(2), h(3), h(4)]);
    let r2 = merkle_root_of_hashes(&[h(4), h(3), h(2), h(1)]);
    assert_ne!(r1, r2);
}

#[test]
fn borsh_leaves_match_pre_hashed_leaves() {
    let items = vec![Leaf(vec![1, 2, 3]), Leaf(vec![4, 5, 6, 7])];
    let pre: Vec<Hash> = items
        .iter()
        .map(|i| {
            let mut bytes = b"TEST_MERKLE_LEAF".to_vec();
            bytes.extend(borsh::to_vec(i).unwrap());
            hash_leaf(&bytes)
        })
        .collect();
    assert_eq!(merkle_root(&items), merkle_root_of_hashes(&pre));
}

#[test]
fn root_is_deterministic_across_repeated_calls() {
    let leaves = [h(1), h(2), h(3), h(4), h(5), h(6), h(7)];
    let r1 = merkle_root_of_hashes(&leaves);
    let r2 = merkle_root_of_hashes(&leaves);
    assert_eq!(r1, r2);
}
