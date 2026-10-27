//! Bounded authenticated history openings and archive-only historical trees.

extern crate alloc;

use alloc::collections::BTreeMap;
use neutrin0_consensus_types::history::{
    HISTORY_DEPTH, HistoryFrontier, HistoryPath, counted_history_root, empty_history_hashes,
    history_leaf_hash, history_node_hash,
};
use neutrin0_primitives::Hash;
use neutrin0_prover_chunk::history::HistoricalChunk;
use neutrin0_storage::{Batch, Column, Database};

use super::{ChainStore, StoreError, keys};
use crate::RetentionPolicy;

mod appends;
mod openings;

#[cfg(test)]
pub(super) mod tests;

fn decode_history_path_key<E>(key: &[u8]) -> Result<(u64, u64), StoreError<E>> {
    let bytes: [u8; 16] = key
        .try_into()
        .map_err(|_| StoreError::Corrupt("history path key length"))?;
    Ok((
        u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes")),
        u64::from_be_bytes(bytes[8..].try_into().expect("eight bytes")),
    ))
}

fn frontier_tree_root<E>(frontier: &HistoryFrontier) -> Result<Hash, StoreError<E>> {
    let empty = empty_history_hashes();
    let mut right = empty[0];
    let mut peaks = frontier.peaks.iter();
    for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
        let (left, sibling) = if (frontier.count >> level) & 1 == 1 {
            (
                *peaks
                    .next()
                    .ok_or(StoreError::Corrupt("history frontier shape"))?,
                right,
            )
        } else {
            (right, *empty_subtree)
        };
        right = history_node_hash(level, left, sibling);
    }
    if peaks.next().is_some()
        || frontier.root() != Some(counted_history_root(frontier.count, right))
    {
        return Err(StoreError::Corrupt("history frontier root mismatch"));
    }
    Ok(right)
}

pub(super) fn put_history_frontier<E>(
    batch: &mut Batch,
    frontier: &HistoryFrontier,
) -> Result<(), StoreError<E>> {
    let root = frontier_tree_root(frontier)?;
    batch.put(
        Column::HistoryFrontiers,
        keys::chunk_id_key(frontier.count),
        borsh::to_vec(&(frontier, root))?,
    );
    Ok(())
}

pub(super) fn put_history_path<E>(
    batch: &mut Batch,
    path: &HistoryPath,
    leaf: Hash,
    expected: Hash,
) -> Result<(), StoreError<E>> {
    if !path.verify(leaf, expected) {
        return Err(StoreError::Corrupt("history opening mismatch"));
    }
    batch.put(
        Column::HistoryPaths,
        keys::pair_key(path.count, path.index),
        borsh::to_vec(&(leaf, path))?,
    );
    Ok(())
}

/// Store an archive's tree nodes from `leaf` up `path` and return the tree
/// root they reach.
pub(super) fn put_path_nodes<E>(
    batch: &mut Batch,
    leaf: Hash,
    path: &HistoryPath,
) -> Result<Hash, StoreError<E>> {
    let mut root = history_leaf_hash(Some(leaf));
    for (level, sibling) in path.siblings.iter().enumerate() {
        let children = if (path.index >> level) & 1 == 0 {
            (root, *sibling)
        } else {
            (*sibling, root)
        };
        root = history_node_hash(level, children.0, children.1);
        batch.put(Column::HistoryNodes, root, borsh::to_vec(&children)?);
    }
    Ok(root)
}

impl<DB: Database> ChainStore<DB> {
    /// Read an immutable finalized historical record.
    pub fn historical_chunk(
        &self,
        id: u64,
    ) -> Result<Option<HistoricalChunk>, StoreError<DB::Error>> {
        let mut record: Option<HistoricalChunk> =
            self.get_decoded(Column::HistoricalChunks, &keys::chunk_id_key(id))?;
        if record.is_none() && self.retention_info()?.policy == RetentionPolicy::Reporter {
            record = self.reporter_record(id)?;
        }
        if record
            .as_ref()
            .is_some_and(|record| record.chunk.chunk_id != id)
        {
            return Err(StoreError::Corrupt("historical record index mismatch"));
        }
        Ok(record)
    }

    fn history_snapshot(
        &self,
        count: u64,
    ) -> Result<(HistoryFrontier, Hash), StoreError<DB::Error>> {
        if count == 0 {
            return Ok((
                HistoryFrontier::empty(),
                empty_history_hashes()[HISTORY_DEPTH],
            ));
        }
        let (frontier, root): (HistoryFrontier, Hash) = self
            .get_decoded(Column::HistoryFrontiers, &keys::chunk_id_key(count))?
            .ok_or(StoreError::Corrupt("history frontier is unavailable"))?;
        if frontier.count != count || frontier.root() != Some(counted_history_root(count, root)) {
            return Err(StoreError::Corrupt("history frontier root mismatch"));
        }
        Ok((frontier, root))
    }

    /// Read the bounded frontier at any retained finalized boundary.
    pub fn history_frontier(&self, count: u64) -> Result<HistoryFrontier, StoreError<DB::Error>> {
        self.history_snapshot(count).map(|(frontier, _)| frontier)
    }

    /// Root of the retained frontier at `count`, read once per validation pass.
    /// Lookup failures are returned and never memoized.
    pub(super) fn cached_history_root(
        &self,
        count: u64,
        roots: &mut BTreeMap<u64, Option<Hash>>,
    ) -> Result<Option<Hash>, StoreError<DB::Error>> {
        if let Some(root) = roots.get(&count) {
            return Ok(*root);
        }
        let root = self.history_frontier(count)?.root();
        roots.insert(count, root);
        Ok(root)
    }

    fn history_children(
        &self,
        root: Hash,
        level: usize,
        empty: &[Hash; 65],
    ) -> Result<(Hash, Hash), StoreError<DB::Error>> {
        if root == empty[level + 1] {
            return Ok((empty[level], empty[level]));
        }
        let children: (Hash, Hash) = self
            .get_decoded(Column::HistoryNodes, &root)?
            .ok_or(StoreError::Corrupt("history node is unavailable"))?;
        if history_node_hash(level, children.0, children.1) != root {
            return Err(StoreError::Corrupt("history node hash mismatch"));
        }
        Ok(children)
    }

    /// Whether an offence was admitted by an already finalized block.
    pub fn is_offence_finalized(&self, id: &Hash) -> Result<bool, StoreError<DB::Error>> {
        self.get_raw(Column::FinalizedOffences, id)
            .map(|value| value.is_some())
    }

    /// Whether a finalized block admitted a safety sanction against this BLS
    /// identity. The permanent tombstone makes every later safety receipt or
    /// raw report against the identity redundant.
    pub fn is_identity_slashed(
        &self,
        pubkey: &neutrin0_primitives::BlsPublicKey,
    ) -> Result<bool, StoreError<DB::Error>> {
        self.get_raw(Column::FinalizedSlashes, pubkey)
            .map(|value| value.is_some())
    }
}

impl<DB: Database> ChainStore<DB> {
    /// Compact public output authenticated by the finalized chunk receipt.
    pub fn chunk_statement(
        &self,
        id: u64,
    ) -> Result<
        Option<neutrin0_consensus_types::history_proof::ConsensusStatement>,
        StoreError<DB::Error>,
    > {
        self.get_checked(
            Column::ChunkStatements,
            &keys::chunk_id_key(id),
            |statement: &neutrin0_consensus_types::history_proof::ConsensusStatement| {
                statement.chunk.chunk_id == id
            },
            "chunk statement key mismatch",
        )
    }

    /// Immutable compact canonical boundary at a covered chunk count.
    pub fn consensus_boundary(
        &self,
        count: u64,
    ) -> Result<
        Option<neutrin0_consensus_types::history_proof::ConsensusBoundary>,
        StoreError<DB::Error>,
    > {
        self.get_checked(
            Column::ConsensusBoundaries,
            &keys::chunk_id_key(count),
            |boundary: &neutrin0_consensus_types::history_proof::ConsensusBoundary| {
                boundary.next_chunk_id == count
            },
            "consensus boundary key mismatch",
        )
    }

    /// Trusted profile persisted independently of peer proof envelopes.
    pub fn history_domain(
        &self,
    ) -> Result<Option<neutrin0_consensus_types::history_proof::ProofDomain>, StoreError<DB::Error>>
    {
        self.get_decoded(Column::Meta, super::pointers::HISTORY_PROOF_DOMAIN)
    }

    /// Register the active program profile once.
    pub(crate) fn set_history_domain(
        &mut self,
        domain: &neutrin0_consensus_types::history_proof::ProofDomain,
    ) -> Result<(), StoreError<DB::Error>> {
        if let Some(previous) = self.history_domain()? {
            return if previous == *domain {
                Ok(())
            } else {
                Err(StoreError::Corrupt("history program profile changed"))
            };
        }
        let mut batch = Batch::new();
        batch.put(
            Column::Meta,
            super::pointers::HISTORY_PROOF_DOMAIN,
            borsh::to_vec(domain)?,
        );
        self.write_observed_batch(batch, false)
    }
}
