//! Host-side state implementations used by the dynamic runtime and the
//! dry-run path that builds witnesses.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use neutrin0_primitives::StateRoot;
use neutrin0_runtime_abi::{StateWitness, TrieNodeBytes, TrieValueBytes};
use neutrin0_trie::{Poseidon2Hasher, Trie, TrieError};

use crate::StateBackend;

/// In-memory state trie used by tests and by the dry-run path.
///
/// Wraps a `neutrin0_trie::Trie<Poseidon2Hasher>` so callers get the
/// canonical state root for free and the same partial-trie
/// reconstruction the SP1 Guest performs.
#[derive(Clone, Debug, Default)]
pub struct LiveTrie {
    trie: Trie<Poseidon2Hasher>,
}

impl LiveTrie {
    /// Wrap an existing trie as a read-only snapshot. Used by the
    /// block producer to take a [`LiveTrie`] view of the engine's
    /// authoritative state trie before invoking the runtime.
    #[must_use]
    pub const fn from_trie(trie: Trie<Poseidon2Hasher>) -> Self {
        Self { trie }
    }

    /// Insert (or overwrite) a value.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        self.trie
            .insert(key, value)
            .expect("trie insert never fails for length-prefixed keys");
    }

    /// Remove a key from the live state.
    pub fn remove(&mut self, key: &[u8]) {
        let _ = self
            .trie
            .remove(key)
            .expect("live trie holds every node on a removed path");
    }

    /// Read the value at `key`.
    ///
    /// # Errors
    /// Returns the trie's error when the live trie does not hold every
    /// node and value on the key's path.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        self.trie.get(key)
    }

    /// Current trie root.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.trie.root()
    }

    /// Borrow the underlying trie (read-only).
    #[must_use]
    pub const fn trie(&self) -> &Trie<Poseidon2Hasher> {
        &self.trie
    }
}

/// Materialise the witness for `accessed` keys against the pre-state
/// trie `live`.
///
/// The witness embeds every trie node along the touched paths (so the
/// Guest can both read and re-root) and the leaf value bytes for
/// present keys. The root node is always included (when the trie is
/// non-empty) so the Guest can bind to the claimed `pre_state_root`
/// even on blocks where the STF reads no state. Shared by
/// [`TracingState`] and the WASM runtime host so both emit identical
/// witnesses.
///
/// # Errors
/// Returns the trie's error when `live` does not hold every node on an
/// accessed path; no witness can describe such a state.
pub fn witness_of(
    live: &Trie<Poseidon2Hasher>,
    accessed: BTreeSet<Vec<u8>>,
) -> Result<StateWitness, TrieError> {
    let pre_root = live.root();
    let mut nodes = BTreeMap::new();
    let mut values = BTreeMap::new();
    for key in &accessed {
        live.collect_path_nodes(key, &mut nodes, &mut values)?;
    }
    // Always include the root node (when present) so an empty
    // access set still produces a witness the Guest can bind to
    // `pre_state_root`.
    if pre_root != neutrin0_trie::EMPTY_TRIE_ROOT
        && let Some(bytes) = live.node_bytes(&pre_root)?
    {
        nodes.entry(pre_root).or_insert(bytes);
    }
    Ok(StateWitness {
        pre_state_root: pre_root,
        nodes: nodes
            .into_iter()
            .map(|(hash, bytes)| TrieNodeBytes { hash, bytes })
            .collect(),
        values: values
            .into_iter()
            .map(|(hash, bytes)| TrieValueBytes { hash, bytes })
            .collect(),
        witnessed_keys: accessed.into_iter().collect(),
    })
}

/// Final value per written key in strictly increasing key order; `None`
/// marks a delete. Applied to the pre-state they reproduce the post-state.
pub type StateWrites = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// `StateBackend` that wraps a [`LiveTrie`] and records every key
/// the STF touches. Used during dry-run so the host can build a
/// [`StateWitness`] for the SP1 Guest.
pub struct TracingState<'a> {
    live: &'a LiveTrie,
    /// Reads + writes performed by the STF.
    accessed: BTreeSet<Vec<u8>>,
    pre_root: StateRoot,
    /// A scratch trie holding `live` plus every write and delete
    /// this run made, so reads see earlier writes and
    /// `post_state_root` is correct without mutating `live`.
    ///
    /// Lazily initialised from `live` on the first write so the
    /// read-only paths stay free.
    scratch: Option<Trie<Poseidon2Hasher>>,
    /// Final value per written key (`None` for a delete), the block's
    /// state diff for proof-following nodes.
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// First trie failure the STF ran into: the live state does not hold
    /// a node or value on an accessed path. The STF cannot be told, so
    /// the read answers "absent" and the execution is condemned when
    /// its results are collected.
    fault: Option<TrieError>,
}

impl<'a> TracingState<'a> {
    /// Wrap a live trie for tracing.
    #[must_use]
    pub const fn new(live: &'a LiveTrie) -> Self {
        Self {
            live,
            accessed: BTreeSet::new(),
            pre_root: live.state_root(),
            scratch: None,
            writes: BTreeMap::new(),
            fault: None,
        }
    }

    /// The first state failure this run hit, if any. Results of a
    /// faulted run are never usable.
    #[must_use]
    pub const fn fault(&self) -> Option<TrieError> {
        self.fault
    }

    /// Materialise the recorded read / write set as a
    /// [`StateWitness`] the SP1 Guest can replay against.
    ///
    /// See [`witness_of`] for the witness contents.
    ///
    /// # Errors
    /// Returns the run's [`Self::fault`] or an incomplete witness path.
    pub fn into_witness(self) -> Result<StateWitness, TrieError> {
        Ok(self.into_committed_and_witness()?.1)
    }

    /// Consume the tracer and return both the **post-state trie**
    /// (with every write applied) and the [`StateWitness`].
    ///
    /// The block producer uses this to advance the engine's
    /// authoritative state trie in lock-step with the witness it
    /// hands to the SP1 prover. The returned trie's
    /// `drain_pending_*` lists carry exactly the new content-
    /// addressed nodes and values produced by this block, so the
    /// engine can flush only the diff to RocksDB.
    ///
    /// If the STF performed no writes the returned trie is a
    /// clone of the live snapshot; the pending lists are empty
    /// and the root equals `pre_state_root`.
    ///
    /// # Errors
    /// Returns the run's [`Self::fault`] or an incomplete witness path.
    pub fn into_committed_and_witness(
        self,
    ) -> Result<(Trie<Poseidon2Hasher>, StateWitness), TrieError> {
        let (post_state, witness, _) = self.into_committed_witness_and_writes()?;
        Ok((post_state, witness))
    }

    /// [`Self::into_committed_and_witness`] plus the final value of
    /// every written key in strictly increasing key order; `None`
    /// marks a delete. Applying the writes to the pre-state trie
    /// reproduces the post-state root.
    ///
    /// # Errors
    /// Returns the run's [`Self::fault`] or an incomplete witness path:
    /// a run over unavailable state produces no post-state, witness or
    /// diff.
    pub fn into_committed_witness_and_writes(
        self,
    ) -> Result<(Trie<Poseidon2Hasher>, StateWitness, StateWrites), TrieError> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        let witness = witness_of(self.live.trie(), self.accessed)?;
        // Read-only blocks fall back to a clone of the live trie
        // so the producer can swap the result back into the
        // engine unconditionally without inspecting the
        // scratch-was-initialised flag.
        let post_state = self.scratch.unwrap_or_else(|| self.live.trie().clone());
        Ok((post_state, witness, self.writes.into_iter().collect()))
    }

    fn ensure_scratch(&mut self) -> &mut Trie<Poseidon2Hasher> {
        // A clone of the underlying `Trie` is a BTreeMap clone, and
        // the STF only writes a handful of keys per block.
        let live = self.live;
        self.scratch.get_or_insert_with(|| live.trie().clone())
    }
}

impl StateBackend for TracingState<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.accessed.insert(key.to_vec());
        // The scratch trie, once present, is `live` with every write
        // and delete of this run applied in order.
        let lookup = self
            .scratch
            .as_ref()
            .map_or_else(|| self.live.get(key), |scratch| scratch.get(key));
        match lookup {
            Ok(value) => value,
            Err(error) => {
                self.fault.get_or_insert(error);
                None
            }
        }
    }

    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        self.accessed.insert(key.to_vec());
        self.writes.insert(key.to_vec(), Some(value.clone()));
        let result = self.ensure_scratch().insert(key, value);
        if let Err(error) = result {
            self.fault.get_or_insert(error);
        }
    }

    fn delete(&mut self, key: &[u8]) {
        self.accessed.insert(key.to_vec());
        self.writes.insert(key.to_vec(), None);
        let result = self.ensure_scratch().remove(key);
        if let Err(error) = result {
            self.fault.get_or_insert(error);
        }
    }

    fn pre_state_root(&self) -> StateRoot {
        self.pre_root
    }

    fn post_state_root(&self) -> StateRoot {
        self.scratch
            .as_ref()
            .map_or(self.pre_root, neutrin0_trie::Trie::root)
    }
}
