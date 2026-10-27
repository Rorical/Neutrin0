//! The Guest-side backend: a partial trie rebuilt from a [`StateWitness`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use neutrin0_primitives::StateRoot;
use neutrin0_runtime_abi::StateWitness;
use neutrin0_trie::{Hasher, Poseidon2Hasher, Trie};

use crate::{EMPTY_STATE_ROOT, StateBackend};

/// Errors thrown when constructing a [`WitnessState`].
#[derive(Debug, Eq, PartialEq)]
pub enum WitnessError {
    /// A `TrieNodeBytes` entry's claimed hash did not match the
    /// canonical Poseidon2 hash of its bytes.
    NodeHashMismatch {
        /// The hash the witness claimed.
        claimed: StateRoot,
    },
    /// A `TrieValueBytes` entry's claimed hash did not match the
    /// canonical Poseidon2 hash of its bytes.
    ValueHashMismatch {
        /// The hash the witness claimed.
        claimed: StateRoot,
    },
    /// The `pre_state_root` is non-empty but no supplied node has a
    /// matching hash, so the root cannot be reconstructed.
    PreRootMissing {
        /// Root the witness claims to commit to.
        claimed: StateRoot,
    },
    /// A declared key cannot be opened completely under the authenticated root.
    IncompletePath {
        /// Key whose on-path node, value or node encoding is missing/invalid.
        key: Vec<u8>,
    },
}

/// `StateBackend` driven entirely by a [`StateWitness`].
///
/// `read` panics for any key not present in `witness.witnessed_keys`, and
/// construction rejects any declared key with an incomplete path or
/// missing value. Writes are applied to the partial trie via
/// `Trie::insert`; `post_state_root` returns the live root.
#[derive(Debug)]
pub struct WitnessState {
    /// Keys explicitly witnessed. Reads outside this set panic.
    witnessed: BTreeSet<Vec<u8>>,
    /// Partial trie carrying every node and value on the touched paths.
    trie: Trie<Poseidon2Hasher>,
    /// Pre-state root claimed by the witness, validated at construction.
    pre_root: StateRoot,
}

impl WitnessState {
    fn authenticate(witness: &StateWitness) -> Result<(), WitnessError> {
        for node in &witness.nodes {
            if Poseidon2Hasher::hash_node(&node.bytes) != node.hash {
                return Err(WitnessError::NodeHashMismatch { claimed: node.hash });
            }
        }
        for value in &witness.values {
            if Poseidon2Hasher::hash_value(&value.bytes) != value.hash {
                return Err(WitnessError::ValueHashMismatch {
                    claimed: value.hash,
                });
            }
        }
        if witness.pre_state_root != EMPTY_STATE_ROOT
            && !witness
                .nodes
                .iter()
                .any(|node| node.hash == witness.pre_state_root)
        {
            return Err(WitnessError::PreRootMissing {
                claimed: witness.pre_state_root,
            });
        }
        // Native consensus validation must reject incomplete peer openings
        // without entering Trie::get's fail-closed panic path. Checking every
        // declared read also authenticates absence before an auxiliary ledger
        // can use it to seat an identity. Inserts use these same complete paths.
        let nodes: BTreeMap<_, _> = witness
            .nodes
            .iter()
            .map(|node| (node.hash, &node.bytes))
            .collect();
        let values: BTreeMap<_, _> = witness
            .values
            .iter()
            .map(|value| (value.hash, &value.bytes))
            .collect();
        for key in &witness.witnessed_keys {
            neutrin0_trie::lookup_persisted(
                witness.pre_state_root,
                key,
                |hash| nodes.get(hash).map(|bytes| (*bytes).clone()),
                |hash| values.get(hash).map(|bytes| (*bytes).clone()),
            )
            .map_err(|_| WitnessError::IncompletePath { key: key.clone() })?;
        }
        Ok(())
    }

    /// Build a `WitnessState` and verify the reconstructed partial
    /// trie's root matches `pre_state_root`. The SP1 Guest calls this
    /// before running the STF; any tamper aborts proving.
    ///
    /// # Errors
    /// Returns [`WitnessError::NodeHashMismatch`] or
    /// [`WitnessError::ValueHashMismatch`] for forged content hashes, or
    /// [`WitnessError::PreRootMissing`] when a non-empty root is absent, or
    /// [`WitnessError::IncompletePath`] for an incomplete declared lookup.
    pub fn new(witness: &StateWitness) -> Result<Self, WitnessError> {
        // (1) Every node and value's claimed hash must match the
        //     canonical Poseidon2 hash of its bytes. The trie's content-
        //     addressed store assumes this invariant; we re-check it
        //     so an adversarial host can't smuggle in a forged node.
        Self::authenticate(witness)?;

        // (2) Build the partial trie after every declared lookup has been
        //     authenticated completely, including paths proving absence.
        let trie = Trie::<Poseidon2Hasher>::from_persisted(
            witness.pre_state_root,
            witness.nodes.iter().map(|n| (n.hash, n.bytes.clone())),
            witness.values.iter().map(|v| (v.hash, v.bytes.clone())),
        );

        let mut witnessed = BTreeSet::new();
        for key in &witness.witnessed_keys {
            witnessed.insert(key.clone());
        }

        Ok(Self {
            witnessed,
            trie,
            pre_root: witness.pre_state_root,
        })
    }

    /// Authenticate and consume a witness, retaining its buffers without copying.
    /// Missing-path and unwitnessed-read rejection are identical to [`Self::new`].
    ///
    /// # Errors
    /// Returns the same content-hash and missing-root errors as [`Self::new`].
    pub fn from_owned(witness: StateWitness) -> Result<Self, WitnessError> {
        Self::authenticate(&witness)?;
        let StateWitness {
            pre_state_root,
            nodes,
            values,
            witnessed_keys,
        } = witness;
        let trie = Trie::<Poseidon2Hasher>::from_persisted(
            pre_state_root,
            nodes.into_iter().map(|node| (node.hash, node.bytes)),
            values.into_iter().map(|value| (value.hash, value.bytes)),
        );
        Ok(Self {
            witnessed: witnessed_keys.into_iter().collect(),
            trie,
            pre_root: pre_state_root,
        })
    }
}

impl StateBackend for WitnessState {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        assert!(
            self.witnessed.contains(key),
            "witness missing entry for key {key:?}"
        );
        // An incomplete witnessed path aborts the Guest: it must never read
        // as absence and prove a forged transition.
        self.trie
            .get(key)
            .expect("witness holds every node and value on a witnessed path")
    }

    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        // Writes implicitly witness the key for the post-root rehash.
        self.witnessed.insert(key.to_vec());
        self.trie
            .insert(key, value)
            .expect("trie insert never fails for length-prefixed keys");
    }

    fn delete(&mut self, key: &[u8]) {
        self.witnessed.insert(key.to_vec());
        let _ = self
            .trie
            .remove(key)
            .expect("witness holds every node on a deleted path");
    }

    fn pre_state_root(&self) -> StateRoot {
        self.pre_root
    }

    fn post_state_root(&self) -> StateRoot {
        self.trie.root()
    }
}
