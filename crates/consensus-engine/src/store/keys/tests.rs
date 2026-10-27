use super::*;

#[test]
fn integer_keys_sort_lexicographically_in_numeric_order() {
    let keys = [
        height_key(0),
        height_key(1),
        height_key(255),
        height_key(256),
        height_key(u64::MAX - 1),
        height_key(u64::MAX),
    ];
    for window in keys.windows(2) {
        assert!(window[0] < window[1]);
    }
}

#[test]
fn slot_chunk_checkpoint_encoders_match_height_encoder() {
    // All four are big-endian 8-byte u64 encoders; this is a tripwire
    // for accidental endianness drift.
    assert_eq!(height_key(0xDEAD_BEEF), slot_key(0xDEAD_BEEF));
    assert_eq!(slot_key(0xDEAD_BEEF), chunk_id_key(0xDEAD_BEEF));
    assert_eq!(chunk_id_key(0xDEAD_BEEF), checkpoint_index_key(0xDEAD_BEEF));
}

#[test]
fn pair_key_concatenates_big_endian_halves() {
    let key = pair_key(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
    assert_eq!(key[..8], 0x0102_0304_0506_0708_u64.to_be_bytes());
    assert_eq!(key[8..], 0x1112_1314_1516_1718_u64.to_be_bytes());
    assert!(pair_key(1, u64::MAX) < pair_key(2, 0));
}

#[test]
fn hash_key_is_identity() {
    let h: BlockHash = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    assert_eq!(hash_key(&h), h);
}
