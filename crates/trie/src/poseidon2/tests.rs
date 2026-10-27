use super::*;

#[test]
fn permutation_singleton_is_idempotent() {
    // OnceBox guarantee — two calls return the same reference.
    let a = core::ptr::from_ref::<KoalaPerm>(perm_instance());
    let b = core::ptr::from_ref::<KoalaPerm>(perm_instance());
    assert_eq!(a, b, "perm_instance must return the same singleton");
}

#[test]
fn empty_input_hashes_to_well_defined_non_zero_digest() {
    // Empty input is the length-prefix block (all zeros after the
    // 8-byte len = 0) plus an absorb-output.  The result must be
    // non-zero and deterministic.
    let h = poseidon2_byte_hash(&[]);
    assert_ne!(h, [0u8; 32]);
    assert_eq!(h, poseidon2_byte_hash(&[]), "deterministic across calls");
}

#[test]
fn distinct_inputs_have_distinct_digests() {
    // Trivial collision-resistance smoke check.
    let a = poseidon2_byte_hash(b"alpha");
    let b = poseidon2_byte_hash(b"beta");
    assert_ne!(a, b);
}

#[test]
fn length_prefix_prevents_zero_extension_collision() {
    // Without the length-prefix block, "a" and "a\0" would
    // produce the same digest because the second is just a
    // zero-padded version of the first inside the same 24-byte
    // block.  The length prefix splits them.
    let a = poseidon2_byte_hash(b"a");
    let ab = poseidon2_byte_hash(b"a\0");
    assert_ne!(a, ab, "length-prefixed sponge must distinguish them");
}

#[test]
fn node_and_value_hashes_are_disjoint_namespaces() {
    // The same input bytes hash differently under hash_node vs
    // hash_value because hash_node prepends
    // TRIE_NODE_DOMAIN_POSEIDON2 first.
    let bytes = b"collision attempt";
    let n = <Poseidon2Hasher as Hasher>::hash_node(bytes);
    let v = <Poseidon2Hasher as Hasher>::hash_value(bytes);
    assert_ne!(n, v);
}

#[test]
fn poseidon2_domain_is_exactly_sixteen_bytes() {
    assert_eq!(TRIE_NODE_DOMAIN_POSEIDON2.len(), 16);
}

#[test]
fn output_top_bit_of_each_element_is_zero() {
    // Each output element is a KoalaBear field element with value
    // < 2^31, so when packed as little-endian u32 the top bit of
    // bytes 3, 7, 11, 15, 19, 23, 27, 31 must be zero.  This is a
    // sanity check that the host-side software path didn't smuggle
    // a value >= modulus through `as_canonical_u32()`.
    let digest = poseidon2_byte_hash(b"sanity check input");
    for i in 0..8 {
        let top_byte = digest[i * 4 + 3];
        assert!(
            top_byte < 0x80,
            "byte {} = 0x{:02x} has the top bit set; element {} would be >= 2^31",
            i * 4 + 3,
            top_byte,
            i,
        );
    }
}
