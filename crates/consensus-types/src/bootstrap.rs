//! Bounded checkpoint metadata and content-addressed state snapshot transport.
//!
//! Decoding these types does not authenticate their contents. A consumer verifies
//! the real chunk receipt, the opening of its local trust anchor, the endpoint
//! context and all historical openings before installing any live chain state. Fragments are
//! authenticated after reconstructing a complete node, value or program. Guest
//! program bytes require local SP1 verifying-key derivation before installation.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_primitives::{BoundedBytes, BoundsError, Hash, Validator};

use crate::{
    Header, HistoryProof,
    history::{HISTORY_RETENTION_CHUNKS, HistoryFrontier},
    history_proof::BoundedVec,
};

/// Maximum active validator vector carried by one bootstrap response.
/// Matches the kernel committee bound; it does not authorize activation.
pub const MAX_BOOTSTRAP_VALIDATORS: usize = neutrin0_primitives::MAX_CONSENSUS_VALIDATORS;
/// Maximum historical openings needed to resume current consensus.
pub const MAX_BOOTSTRAP_HISTORY_RECORDS: usize = 8;
const _: () = assert!(HISTORY_RETENTION_CHUNKS == 8);
/// Aggregate encoded opening bytes carried by one bootstrap response.
pub const MAX_BOOTSTRAP_HISTORY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum content-addressed items requested or returned in one state response.
pub const MAX_STATE_ITEMS: usize = 128;
/// Maximum bytes of one node or value fragment.
pub const MAX_STATE_FRAGMENT_BYTES: usize = 64 * 1024;

/// Bounded active validator set at the authenticated checkpoint endpoint.
pub type BootstrapValidators = BoundedVec<Validator, MAX_BOOTSTRAP_VALIDATORS>;
/// Canonical encoded historical openings, without a dependency on the prover.
pub type BootstrapHistory =
    BoundedVec<BoundedBytes<MAX_BOOTSTRAP_HISTORY_BYTES>, MAX_BOOTSTRAP_HISTORY_RECORDS>;

/// Metadata needed to initialize a full node from a verified History proof.
/// An execution-state snapshot is fetched separately under its end's root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapData {
    /// Receipt of the chunk ending at the endpoint, which proves the chain from
    /// the specification's start (genesis, or a hard fork's start). Any other
    /// local trust origin additionally requires an anchor opening. The next
    /// certificate ratifies this very receipt, which ends at the next chunk's
    /// start (design 08).
    pub history: HistoryProof,
    /// Header at the end boundary, retained as the canonical parent anchor.
    pub anchor_header: Header,
    /// Ordered active validators effective for the next chunk.
    pub validators: BootstrapValidators,
    /// Counted history frontier at the same endpoint.
    pub frontier: HistoryFrontier,
    /// Exact preceding window of encoded `HistoricalOpening` objects.
    /// Their paths target the endpoint's history root and count.
    pub recent: BootstrapHistory,
}

impl BootstrapData {
    /// Construct metadata with both element and aggregate byte bounds checked.
    pub fn new(
        history: HistoryProof,
        anchor_header: Header,
        validators: Vec<Validator>,
        frontier: HistoryFrontier,
        recent: Vec<BoundedBytes<MAX_BOOTSTRAP_HISTORY_BYTES>>,
    ) -> Result<Self, BoundsError> {
        let data = Self {
            history,
            anchor_header,
            validators: BootstrapValidators::new(validators)?,
            frontier,
            recent: BootstrapHistory::new(recent)?,
        };
        data.validate_limits()?;
        Ok(data)
    }

    /// Check the cumulative historical byte limit on a locally constructed value.
    pub fn validate_limits(&self) -> Result<(), BoundsError> {
        let actual = self.recent.iter().map(BoundedBytes::len).sum();
        if actual > MAX_BOOTSTRAP_HISTORY_BYTES {
            return Err(BoundsError {
                actual,
                max: MAX_BOOTSTRAP_HISTORY_BYTES,
            });
        }
        Ok(())
    }
}

impl BorshSerialize for BootstrapData {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        self.validate_limits()
            .map_err(|_| invalid_data("bootstrap historical byte budget"))?;
        self.history.serialize(writer)?;
        self.anchor_header.serialize(writer)?;
        self.validators.serialize(writer)?;
        self.frontier.serialize(writer)?;
        self.recent.serialize(writer)
    }
}

impl BorshDeserialize for BootstrapData {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let history = HistoryProof::deserialize_reader(reader)?;
        let anchor_header = Header::deserialize_reader(reader)?;
        let validators = BootstrapValidators::deserialize_reader(reader)?;
        let frontier = HistoryFrontier::deserialize_reader(reader)?;
        let count = u32::deserialize_reader(reader)? as usize;
        if count > MAX_BOOTSTRAP_HISTORY_RECORDS {
            return Err(invalid_data("bootstrap historical record count"));
        }
        let mut budget = MAX_BOOTSTRAP_HISTORY_BYTES;
        let mut recent = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u32::deserialize_reader(reader)? as usize;
            budget = budget
                .checked_sub(length)
                .ok_or_else(|| invalid_data("bootstrap historical byte budget"))?;
            let mut bytes = alloc::vec![0; length];
            reader.read_exact(&mut bytes)?;
            recent.push(
                BoundedBytes::new(bytes)
                    .map_err(|_| invalid_data("bootstrap historical byte budget"))?,
            );
        }
        Ok(Self {
            history,
            anchor_header,
            validators,
            frontier,
            recent: BootstrapHistory::new(recent)
                .map_err(|_| invalid_data("bootstrap historical record count"))?,
        })
    }
}

/// Snapshot object namespace, distinguishing trie objects and execution programs.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize,
)]
pub enum StateItemKind {
    /// Canonically encoded trie node, hashed under the node namespace.
    Node,
    /// Raw runtime value bytes, hashed under the value namespace.
    Value,
    /// Runtime WASM authenticated by its raw BLAKE3 code hash.
    Runtime,
    /// Execution Guest ELF authenticated by its locally derived SP1 key digest.
    /// The request hash is the digest's eight little-endian u32 words.
    Guest,
}

/// An exact snapshot fragment request under an already authenticated state root.
/// Program identities additionally come from its endpoint/recent consensus context.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize,
)]
pub struct StateItem {
    /// Namespace of the object.
    pub kind: StateItemKind,
    /// Complete node/value content hash, runtime BLAKE3 hash, or a Guest's eight
    /// little-endian verifying-key words. Never a hash of the fragment.
    pub hash: Hash,
    /// Byte offset of the requested fragment.
    pub offset: u64,
}

impl StateItem {
    /// Start fetching one trie node by its complete content hash.
    #[must_use]
    pub const fn node(hash: Hash) -> Self {
        Self {
            kind: StateItemKind::Node,
            hash,
            offset: 0,
        }
    }

    /// Start fetching one runtime value by its complete content hash.
    #[must_use]
    pub const fn value(hash: Hash) -> Self {
        Self {
            kind: StateItemKind::Value,
            hash,
            offset: 0,
        }
    }

    /// Fetch one runtime artifact under an authenticated consensus code hash.
    #[must_use]
    pub const fn runtime(hash: Hash) -> Self {
        Self {
            kind: StateItemKind::Runtime,
            hash,
            offset: 0,
        }
    }

    /// Fetch one execution Guest under an authenticated SP1 identity.
    #[must_use]
    pub fn guest(digest: crate::history_proof::VkDigest) -> Self {
        let mut hash = [0; 32];
        for (word, output) in digest.iter().zip(hash.as_chunks_mut::<4>().0) {
            *output = word.to_le_bytes();
        }
        Self {
            kind: StateItemKind::Guest,
            hash,
            offset: 0,
        }
    }

    /// Decode the requested Guest identity without interpreting it as a chain hash.
    #[must_use]
    pub fn guest_digest(&self) -> Option<crate::history_proof::VkDigest> {
        if self.kind != StateItemKind::Guest {
            return None;
        }
        let mut digest = [0; 8];
        for (output, bytes) in digest.iter_mut().zip(self.hash.as_chunks::<4>().0) {
            *output = u32::from_le_bytes(*bytes);
        }
        Some(digest)
    }
}

/// One bounded fragment of a requested trie node, runtime value or execution program.
/// Large objects use successive offsets without changing their complete hash.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct StateEntry {
    /// Exact request this entry answers, including its offset.
    pub item: StateItem,
    /// Length of the complete object; this is untrusted until its hash verifies.
    /// Consumers must not allocate this many bytes directly from the declaration.
    pub total_len: u64,
    /// Bytes starting at the requested offset.
    pub bytes: BoundedBytes<MAX_STATE_FRAGMENT_BYTES>,
}

impl StateEntry {
    /// End offset, rejecting integer overflow.
    #[must_use]
    pub fn end_offset(&self) -> Option<u64> {
        self.item
            .offset
            .checked_add(u64::try_from(self.bytes.len()).ok()?)
    }

    /// Require an exact requested item and a bounded, advancing response.
    /// Every fragment but the last carries exactly [`MAX_STATE_FRAGMENT_BYTES`],
    /// so an object arrives in a bounded number of fragments however a
    /// provider would cut it. Empty values and an empty final fragment are
    /// permitted.
    #[must_use]
    pub fn validate_for(&self, requested: &StateItem) -> bool {
        self.item == *requested
            && self.item.offset <= self.total_len
            && self.end_offset().is_some_and(|end| end <= self.total_len)
            && (self.bytes.len() == MAX_STATE_FRAGMENT_BYTES || self.is_complete())
    }

    /// Whether these bytes reach the declared end of the complete object.
    /// This is a framing property, not content authentication.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.end_offset() == Some(self.total_len)
    }
}

/// Bounded exact fragment requests for one state root.
pub type StateItems = BoundedVec<StateItem, MAX_STATE_ITEMS>;
/// Bounded fragment responses, with at most eight MiB of payload bytes.
pub type StateEntries = BoundedVec<StateEntry, MAX_STATE_ITEMS>;

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
