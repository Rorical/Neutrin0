//! Error type returned by trie construction and proof verification.

use core::fmt;

/// Failure modes for trie operations and proof decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrieError {
    /// A malformed internal bit path is a strict prefix of an
    /// existing path, or vice versa. Public byte-string keys are
    /// length-prefixed before insertion, so this should not occur for
    /// normal callers.
    PrefixCollision,
    /// A node encoding ended before the structure was complete.
    TruncatedNode,
    /// A node encoding had bytes left over after the structure was
    /// fully decoded.
    TrailingNodeBytes,
    /// A node tag byte did not match any known node kind.
    InvalidNodeTag(u8),
    /// A bit-path encoding had nonzero padding bits in the trailing
    /// byte and so is not the canonical representation.
    NonCanonicalBitPath,
    /// A bit-path declared more bits than `u32::MAX / 8` would fit
    /// into bytes; this can only happen for an attacker-supplied
    /// encoding.
    BitPathTooLong,
    /// A retained root reaches a missing node or value.
    MissingRetainedEntry,
    /// A retained node or value does not match its content address.
    RetainedHashMismatch,
}

impl fmt::Display for TrieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixCollision => f.write_str("trie keys must not be prefixes of each other"),
            Self::TruncatedNode => f.write_str("trie node encoding ended unexpectedly"),
            Self::TrailingNodeBytes => f.write_str("trie node encoding had trailing bytes"),
            Self::InvalidNodeTag(tag) => write!(f, "trie node tag {tag:#04x} is not recognised"),
            Self::NonCanonicalBitPath => {
                f.write_str("trie bit-path encoding had nonzero padding bits")
            }
            Self::BitPathTooLong => {
                f.write_str("trie bit-path length does not fit in a byte buffer")
            }
            Self::MissingRetainedEntry => f.write_str("retained trie entry is missing"),
            Self::RetainedHashMismatch => f.write_str("retained trie entry hash mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TrieError {}
