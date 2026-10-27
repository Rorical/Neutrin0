//! Trie node enum, canonical encoding, and node-tag constants.

use alloc::vec::Vec;

use neutrin0_primitives::Hash;

use crate::bits::BitPath;
use crate::error::TrieError;

/// First byte of a leaf node's encoding.
pub const NODE_TAG_LEAF: u8 = 0x00;
/// First byte of a branch node's encoding.
pub const NODE_TAG_BRANCH: u8 = 0x01;
/// First byte of an extension node's encoding.
pub const NODE_TAG_EXTENSION: u8 = 0x02;

/// Canonical wire shape for one trie node.
///
/// Encoding (each variant starts with its `NODE_TAG_*` byte):
///
/// * `Leaf`: `0x00 || BitPath(key_suffix) || value_hash[32]`.
/// * `Branch`: `0x01 || left[32] || right[32]`.
/// * `Extension`: `0x02 || BitPath(prefix) || child[32]`.
///
/// The full encoding is hashed by [`crate::Hasher::hash_node`] (with a
/// domain tag prepended by the implementation) to produce the node's
/// content-addressed identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// Terminal node holding the value hash for a single key.
    Leaf {
        /// Bits of the key that were not consumed by ancestors.
        key_suffix: BitPath,
        /// Hash of the stored value bytes.
        value_hash: Hash,
    },
    /// Two-way branch on the next bit of the path.
    Branch {
        /// Hash of the subtree taken when the next bit is `0`.
        /// `[0; 32]` represents an empty subtree on this side.
        left: Hash,
        /// Hash of the subtree taken when the next bit is `1`.
        /// `[0; 32]` represents an empty subtree on this side.
        right: Hash,
    },
    /// Compressed run of bits shared by every key in the subtree below.
    Extension {
        /// Bits the path must match before descending into `child`.
        prefix: BitPath,
        /// Hash of the subtree below the prefix; never `[0; 32]`.
        child: Hash,
    },
}

impl Node {
    /// Append the canonical encoding to `buf`.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Leaf {
                key_suffix,
                value_hash,
            } => {
                buf.push(NODE_TAG_LEAF);
                key_suffix.encode_into(buf);
                buf.extend_from_slice(value_hash);
            }
            Self::Branch { left, right } => {
                buf.push(NODE_TAG_BRANCH);
                buf.extend_from_slice(left);
                buf.extend_from_slice(right);
            }
            Self::Extension { prefix, child } => {
                buf.push(NODE_TAG_EXTENSION);
                prefix.encode_into(buf);
                buf.extend_from_slice(child);
            }
        }
    }

    /// Encode self into a fresh `Vec`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    /// Parse one canonical encoding. The encoding must consume the
    /// entire input slice; trailing bytes are an error.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrieError> {
        if bytes.is_empty() {
            return Err(TrieError::TruncatedNode);
        }
        let tag = bytes[0];
        let body = &bytes[1..];
        match tag {
            NODE_TAG_LEAF => {
                let (key_suffix, consumed) = BitPath::decode(body)?;
                let value_hash = decode_hash_tail(&body[consumed..])?;
                Ok(Self::Leaf {
                    key_suffix,
                    value_hash,
                })
            }
            NODE_TAG_BRANCH => {
                if body.len() < 64 {
                    return Err(TrieError::TruncatedNode);
                }
                if body.len() > 64 {
                    return Err(TrieError::TrailingNodeBytes);
                }
                let mut left = [0_u8; 32];
                let mut right = [0_u8; 32];
                left.copy_from_slice(&body[..32]);
                right.copy_from_slice(&body[32..64]);
                Ok(Self::Branch { left, right })
            }
            NODE_TAG_EXTENSION => {
                let (prefix, consumed) = BitPath::decode(body)?;
                let child = decode_hash_tail(&body[consumed..])?;
                Ok(Self::Extension { prefix, child })
            }
            other => Err(TrieError::InvalidNodeTag(other)),
        }
    }
}

const fn decode_hash_tail(tail: &[u8]) -> Result<Hash, TrieError> {
    if tail.len() < 32 {
        return Err(TrieError::TruncatedNode);
    }
    if tail.len() > 32 {
        return Err(TrieError::TrailingNodeBytes);
    }
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(tail);
    Ok(hash)
}

#[cfg(test)]
mod tests;
