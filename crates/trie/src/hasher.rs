//! Hash-function abstraction and the BLAKE3 reference implementation.
//!
//! The trie hashes node encodings with a 16-byte domain tag prepended,
//! so node hashes cannot collide with values, headers, signatures, or
//! any other use of the same hash function. Value hashes (the contents
//! of [`crate::node::Node::Leaf::value_hash`]) are plain hashes of the
//! value bytes; the value column in the storage layer is a content-
//! addressable store, so its address space is naturally separated from
//! trie-node hashes by the node-side domain tag.

use alloc::vec::Vec;

use neutrin0_primitives::{Hash, blake3_256};

/// 16-byte domain tag prepended to every trie node before hashing.
pub const TRIE_NODE_DOMAIN: [u8; 16] = *b"NEUTRIN0_TR_NODE";

/// Hash-function plugin used by the trie. Implementations must be
/// stateless and deterministic.
pub trait Hasher {
    /// Hash one canonical trie node encoding. The implementation is
    /// expected to prepend [`TRIE_NODE_DOMAIN`] (or another fixed
    /// domain tag of its choice) before hashing so trie-node hashes
    /// cannot collide with other uses of the same hash function.
    fn hash_node(encoded_node: &[u8]) -> Hash;

    /// Hash a stored value to produce its content-addressed key.
    fn hash_value(value: &[u8]) -> Hash;
}

/// BLAKE3-backed [`Hasher`], the reference implementation for generic trie
/// consumers and tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    fn hash_node(encoded_node: &[u8]) -> Hash {
        let mut buf = Vec::with_capacity(TRIE_NODE_DOMAIN.len() + encoded_node.len());
        buf.extend_from_slice(&TRIE_NODE_DOMAIN);
        buf.extend_from_slice(encoded_node);
        blake3_256(&buf)
    }

    fn hash_value(value: &[u8]) -> Hash {
        blake3_256(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_hash_includes_domain_tag() {
        // Hashing the empty node encoding via the trait must equal
        // BLAKE3(domain_tag), not BLAKE3([]); this is the whole point
        // of the prepended domain tag.
        let direct = blake3_256(&TRIE_NODE_DOMAIN);
        assert_eq!(<Blake3Hasher as Hasher>::hash_node(&[]), direct);
        assert_ne!(<Blake3Hasher as Hasher>::hash_node(&[]), blake3_256(&[]));
    }

    #[test]
    fn value_hash_is_plain_blake3() {
        let value = b"hello world";
        assert_eq!(
            <Blake3Hasher as Hasher>::hash_value(value),
            blake3_256(value)
        );
    }

    #[test]
    fn node_and_value_hashes_are_disjoint_namespaces() {
        // Same input bytes yield different hashes when interpreted as
        // nodes vs values, thanks to the node-side domain tag.
        let bytes = b"collision attempt";
        assert_ne!(
            <Blake3Hasher as Hasher>::hash_node(bytes),
            <Blake3Hasher as Hasher>::hash_value(bytes)
        );
    }

    #[test]
    fn trie_node_domain_is_exactly_sixteen_bytes() {
        assert_eq!(TRIE_NODE_DOMAIN.len(), 16);
    }
}
