//! Per-call host state behind the imports: the scratch trie, recorded
//! accesses and writes, and the bounds on guest-addressed memory.

use std::collections::{BTreeMap, BTreeSet};

use neutrin0_primitives::StateRoot;
use neutrin0_trie::{Poseidon2Hasher, Trie};
use wasmtime::StoreLimits;

use super::limits::store_limits;

pub(super) struct HostState {
    /// Root of the borrowed pre-state trie, reported to the guest.
    pub(super) pre_root: StateRoot,
    /// Scratch copy of the pre-state trie. Reads and writes go here so
    /// the guest sees its own writes and the correct `post_state_root`
    /// without mutating the caller's trie. Discarded after read-only
    /// calls so no mutation can leak back.
    pub(super) scratch: Trie<Poseidon2Hasher>,
    /// Keys the STF has read or written. Becomes the witness key set
    /// and drives node extraction.
    pub(super) accessed: BTreeSet<Vec<u8>>,
    /// Final value per written key (`None` for a delete): the block's
    /// state diff served to proof-following nodes.
    pub(super) writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Value bytes stashed by `state_read_len` so the follow-up
    /// `state_read_into` call can copy them into guest memory.
    pub(super) pending_read_value: Option<Vec<u8>>,
    /// `true` for query-mode invocations: `state_write` and
    /// `state_delete` calls from the guest are silently dropped and
    /// flip [`Self::write_attempted`].
    pub(super) read_only: bool,
    /// Set by [`register_host_imports`](super::host_imports::register_host_imports)
    /// when the guest attempts a write in read-only mode. The caller substitutes
    /// [`neutrin0_runtime_abi::QueryStatus::PermissionDenied`] for the
    /// runtime's response when this flag is set.
    pub(super) write_attempted: bool,
    /// Linear-memory cap enforced by wasmtime's resource limiter.
    pub(super) limits: StoreLimits,
}

impl HostState {
    /// Fresh host state over a scratch copy of `live`, the one trie copy a
    /// call needs because the store must own its data.
    pub(super) fn new(live: &Trie<Poseidon2Hasher>, read_only: bool, memory_bytes: usize) -> Self {
        Self {
            pre_root: live.root(),
            scratch: live.clone(),
            accessed: BTreeSet::new(),
            writes: BTreeMap::new(),
            pending_read_value: None,
            read_only,
            write_attempted: false,
            limits: store_limits(memory_bytes),
        }
    }

    /// Stash the value at `key` for the follow-up copy and return its length,
    /// or `-1` for an absent key. Reads honour the scratch trie because that
    /// captures both live state and any writes the guest already made. State
    /// the host does not hold traps the run instead of reading as absence.
    pub(super) fn read_len(&mut self, key: &[u8]) -> wasmtime::Result<i32> {
        self.accessed.insert(key.to_vec());
        let value = match self.scratch.get(key) {
            Ok(Some(value)) => value,
            Ok(None) => {
                self.pending_read_value = None;
                return Ok(-1);
            }
            Err(error) => {
                return Err(wasmtime::Error::msg(format!(
                    "state unavailable: {error:?}"
                )));
            }
        };
        // `-1` means absent, so a present length must be a non-negative `i32`.
        let len = i32::try_from(value.len())
            .map_err(|_| wasmtime::Error::msg("state value length exceeds i32::MAX"))?;
        self.pending_read_value = Some(value);
        Ok(len)
    }

    pub(super) fn write(&mut self, key: &[u8], value: Vec<u8>) -> wasmtime::Result<()> {
        self.accessed.insert(key.to_vec());
        // `TrieError` implements `std::error::Error` only when the trie's
        // `std` feature is unified in, so convert it explicitly.
        self.scratch
            .insert(key, value.clone())
            .map_err(|error| wasmtime::Error::msg(format!("state write rejected: {error:?}")))?;
        self.writes.insert(key.to_vec(), Some(value));
        Ok(())
    }

    pub(super) fn delete(&mut self, key: &[u8]) -> wasmtime::Result<()> {
        self.accessed.insert(key.to_vec());
        self.scratch
            .remove(key)
            .map_err(|error| wasmtime::Error::msg(format!("state delete rejected: {error:?}")))?;
        self.writes.insert(key.to_vec(), None);
        Ok(())
    }
}

/// Longest state key the trie can address: its length-prefixed bit path of
/// `4 + len` bytes must count its bits in a `u32`. Longer keys trap instead of
/// reaching the trie's panic.
pub(super) const MAX_STATE_KEY_BYTES: usize = (u32::MAX / 8) as usize - 4;

/// The `len` bytes of `memory` at `ptr`, or `None` when the range leaves it.
/// Checked before the host copies or allocates anything for the range.
pub(super) fn guest_slice(memory: &[u8], ptr: u32, len: u32) -> Option<&[u8]> {
    let start = ptr as usize;
    memory.get(start..start.checked_add(len as usize)?)
}
