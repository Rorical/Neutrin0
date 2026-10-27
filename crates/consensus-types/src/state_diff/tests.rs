use super::*;
use alloc::vec;

fn write(key: &[u8], value: Option<&[u8]>) -> StateWrite {
    StateWrite {
        key: key.to_vec(),
        value: value.map(<[u8]>::to_vec),
    }
}

#[test]
fn strictly_increasing_keys_are_canonical() {
    let writes = vec![
        write(b"a", Some(b"1")),
        write(b"ab", None),
        write(b"b", Some(b"")),
    ];
    assert!(super::writes_canonical(&writes));
}

#[test]
fn duplicate_or_unsorted_keys_are_rejected() {
    let duplicate = vec![write(b"a", Some(b"1")), write(b"a", None)];
    assert!(!super::writes_canonical(&duplicate));
    let unsorted = vec![write(b"b", None), write(b"a", None)];
    assert!(!super::writes_canonical(&unsorted));
    assert!(super::writes_canonical(&[]));
}

#[test]
fn borsh_round_trip_preserves_deletes() {
    let diff = BlockStateDiff {
        height: 7,
        block_hash: [1; 32],
        state_root_before: [2; 32],
        state_root_after: [3; 32],
        writes: vec![write(b"k", None), write(b"l", Some(b"v"))],
    };
    let bytes = borsh::to_vec(&diff).unwrap();
    let decoded: BlockStateDiff = borsh::from_slice(&bytes).unwrap();
    assert_eq!(decoded, diff);
    assert_eq!(super::diff_encoded_len(&diff.writes), bytes.len());
}

#[test]
fn imports_refuse_diffs_beyond_the_production_ceiling() {
    let writes = |value_len: usize| vec![write(b"k", Some(&vec![7; value_len]))];
    // The fixed fields, one write's prefixes and its one-byte key.
    let overhead = 8 + 32 + 32 + 32 + 4 + 4 + 1 + 1 + 4;
    let fits = MAX_STATE_DIFF_BYTES - overhead;
    assert!(super::writes_canonical(&writes(fits)));
    assert!(!super::writes_canonical(&writes(fits + 1)));
}
