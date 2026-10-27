//! Streaming installation of a downloaded state snapshot.
//!
//! A snapshot never sits in memory whole. Its roots are pinned first, then
//! the same depth-first walk that persists a block's state counts their
//! edges a bounded slice at a time, reading each entry the store lacks from
//! the download and checking it against its hash. The edges still uncounted
//! persist with every slice, at most two per trie level, so a restart
//! resumes where the last slice ended. Once begun, an installation runs to
//! completion: its partial nodes count edges to entries not yet written,
//! which only finishing can supply. A finished installation is then
//! adopted (its pins become the snapshot's block, or the live sanctions
//! trie) or released like any other pin.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::Hash;
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_trie::{Hasher, NodeSource, Poseidon2Hasher};

use super::state::{NODE, queue_release};
use super::{ChainStore, StatePin, StoreError};

/// Meta key of the installation in progress or awaiting adoption.
const STATE_INSTALL: &[u8] = b"state_install";

/// An installation: its roots, each held by [`StatePin::Install`] at its
/// position, and the edges below them not yet counted.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
struct Installation {
    roots: Vec<Hash>,
    pending: Vec<Hash>,
}

/// The roots of the installation a store holds, in order, and whether it is
/// finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateInstall {
    /// Roots being installed, in order.
    pub roots: Vec<Hash>,
    /// Whether every edge below them is counted.
    pub finished: bool,
}

/// A source whose entries must hash to the key they are read under; any
/// other entry reads as missing.
#[derive(Debug)]
struct Checked<'a>(&'a dyn NodeSource);

impl NodeSource for Checked<'_> {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.0
            .node(hash)
            .filter(|bytes| Poseidon2Hasher::hash_node(bytes) == *hash)
    }

    fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.0
            .value(hash)
            .filter(|bytes| Poseidon2Hasher::hash_value(bytes) == *hash)
    }
}

impl<DB: Database> ChainStore<DB> {
    fn installation(&self) -> Result<Option<Installation>, StoreError<DB::Error>> {
        self.get_decoded(Column::Meta, STATE_INSTALL)
    }

    /// The installation held here, if any.
    ///
    /// # Errors
    /// Reports database or decoding failures.
    pub fn state_install(&self) -> Result<Option<StateInstall>, StoreError<DB::Error>> {
        Ok(self.installation()?.map(|installation| StateInstall {
            finished: installation.pending.is_empty(),
            roots: installation.roots,
        }))
    }

    /// Install `roots` from `source`, counting at most `limit` edges, and
    /// report whether they are now completely stored. A finished
    /// installation of other roots is released first.
    ///
    /// # Errors
    /// Refuses while another installation is unfinished, and reports an
    /// entry `source` lacks or misaddresses as corruption; the slice then
    /// writes nothing.
    pub fn install_state_slice(
        &mut self,
        roots: &[Hash],
        source: &dyn NodeSource,
        limit: usize,
    ) -> Result<bool, StoreError<DB::Error>> {
        let mut batch = Batch::new();
        let mut installation = match self.installation()? {
            Some(installation) if installation.roots == roots => installation,
            Some(installation) if !installation.pending.is_empty() => {
                return Err(StoreError::Corrupt(
                    "another state installation is unfinished",
                ));
            }
            stale => {
                if let Some(stale) = stale {
                    release_batch(&mut batch, &stale);
                }
                for (index, root) in (0_u8..).zip(roots) {
                    batch.put(Column::StatePins, StatePin::Install(index).key(), root);
                }
                Installation {
                    roots: roots.to_vec(),
                    pending: roots.iter().rev().copied().collect(),
                }
            }
        };
        if installation.pending.is_empty() && batch.operations().is_empty() {
            return Ok(true);
        }
        self.state_writer(&mut batch).reference_pending(
            &mut installation.pending,
            limit,
            &Checked(source),
        )?;
        batch.put(Column::Meta, STATE_INSTALL, borsh::to_vec(&installation)?);
        self.write_observed_batch(batch, false)?;
        Ok(installation.pending.is_empty())
    }

    /// Release a finished installation that nothing adopted.
    ///
    /// # Errors
    /// Refuses an unfinished installation, whose partial counts only
    /// finishing can complete.
    pub fn release_state_install(&mut self) -> Result<(), StoreError<DB::Error>> {
        let Some(installation) = self.installation()? else {
            return Ok(());
        };
        if !installation.pending.is_empty() {
            return Err(StoreError::Corrupt("state installation is unfinished"));
        }
        let mut batch = Batch::new();
        release_batch(&mut batch, &installation);
        self.write_observed_batch(batch, true)
    }

    /// Stage the adoption of the finished installation of exactly `roots`:
    /// the root at each position moves to the pin `adopt` names, with its
    /// reference. The caller has released whatever those pins held.
    ///
    /// # Errors
    /// Refuses unless exactly `roots` are completely installed.
    pub(crate) fn adopt_state_install_batch(
        &self,
        batch: &mut Batch,
        roots: &[Hash],
        adopt: &[StatePin],
    ) -> Result<(), StoreError<DB::Error>> {
        if self.installation()?.is_none_or(|installation| {
            installation.roots != roots || !installation.pending.is_empty()
        }) || roots.len() != adopt.len()
        {
            return Err(StoreError::Corrupt("state snapshot is not installed"));
        }
        for ((index, root), pin) in (0_u8..).zip(roots).zip(adopt) {
            batch.delete(Column::StatePins, StatePin::Install(index).key());
            batch.put(Column::StatePins, pin.key(), root);
        }
        batch.delete(Column::Meta, STATE_INSTALL);
        Ok(())
    }
}

/// Unpin a finished installation's roots, queueing their release.
fn release_batch(batch: &mut Batch, installation: &Installation) {
    for (index, root) in (0_u8..).zip(&installation.roots) {
        batch.delete(Column::StatePins, StatePin::Install(index).key());
        queue_release(batch, NODE, *root);
    }
    batch.delete(Column::Meta, STATE_INSTALL);
}
