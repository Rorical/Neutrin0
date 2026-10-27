//! Bounded prefix frontier of the History tree.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_primitives::Hash;

use super::{
    EMPTY_HISTORY_HASHES, HISTORY_DEPTH, HistoryPath, HistorySubtree, counted_history_root,
    history_leaf_hash, history_node_hash, level_byte, subtree_complete,
};

/// Bounded prefix frontier; peaks correspond to set count bits, low to high.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct HistoryFrontier {
    /// Number of occupied consecutive slots starting at zero.
    pub count: u64,
    /// Exactly one complete subtree root for each set bit of `count`.
    pub peaks: Vec<Hash>,
}

impl BorshDeserialize for HistoryFrontier {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let count = u64::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)?;
        if length != count.count_ones() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history frontier shape",
            ));
        }
        let peaks = (0..length)
            .map(|_| Hash::deserialize_reader(reader))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { count, peaks })
    }
}

impl HistoryFrontier {
    /// Frontier for the empty history.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            count: 0,
            peaks: Vec::new(),
        }
    }

    /// Build a frontier from archived context commitments.
    #[must_use]
    pub fn from_leaves(leaves: &[Hash]) -> Option<Self> {
        let mut frontier = Self::empty();
        for leaf in leaves {
            frontier.append(*leaf)?;
        }
        Some(frontier)
    }

    /// Authenticate the canonical prefix shape and derive its counted root.
    #[must_use]
    pub fn root(&self) -> Option<Hash> {
        if self.peaks.len() != self.count.count_ones() as usize {
            return None;
        }
        let empty = &EMPTY_HISTORY_HASHES;
        let mut right = empty[0];
        let mut peaks = self.peaks.iter();
        for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
            right = if (self.count >> level) & 1 == 1 {
                history_node_hash(level, *peaks.next()?, right)
            } else {
                history_node_hash(level, right, *empty_subtree)
            };
        }
        Some(counted_history_root(self.count, right))
    }

    /// Append at the only permitted empty position, without a full-history scan.
    /// Invalid shape or exhausted indexes leave the frontier unchanged.
    pub fn append(&mut self, leaf: Hash) -> Option<Hash> {
        let next = self.count.checked_add(1)?;
        if self.peaks.len() != self.count.count_ones() as usize {
            return None;
        }
        let consumed = self.count.trailing_ones() as usize;
        let mut node = history_leaf_hash(Some(leaf));
        for (level, left) in self.peaks.iter().take(consumed).enumerate() {
            node = history_node_hash(level, *left, node);
        }
        let mut peaks = Vec::with_capacity(self.peaks.len() - consumed + 1);
        peaks.push(node);
        peaks.extend_from_slice(&self.peaks[consumed..]);
        self.count = next;
        self.peaks = peaks;
        self.root()
    }

    /// Open the next appended leaf using only this bounded frontier.
    /// Invalid shape or exhausted indexes return no path; the frontier is unchanged.
    #[must_use]
    pub fn append_path(&self, leaf: Hash) -> Option<HistoryPath> {
        let count = self.count.checked_add(1)?;
        if self.peaks.len() != self.count.count_ones() as usize {
            return None;
        }
        let empty = &EMPTY_HISTORY_HASHES;
        let mut peaks = self.peaks.iter();
        let mut siblings = Vec::with_capacity(HISTORY_DEPTH);
        for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
            siblings.push(if (self.count >> level) & 1 == 1 {
                *peaks.next()?
            } else {
                *empty_subtree
            });
        }
        let path = HistoryPath {
            index: self.count,
            count,
            siblings,
        };
        let mut next = self.clone();
        path.verify(leaf, next.append(leaf)?).then_some(path)
    }
}

impl HistoryFrontier {
    /// The complete subtrees appending `leaf` forms: the leaf itself and each
    /// peak it merges into. A store holding these for every append can open
    /// any leaf with [`Self::open`] instead of advancing one path per leaf.
    /// Invalid shape or exhausted indexes return `None`.
    #[must_use]
    pub fn completed_subtrees(&self, leaf: Hash) -> Option<Vec<HistorySubtree>> {
        self.count.checked_add(1)?;
        if self.peaks.len() != self.count.count_ones() as usize {
            return None;
        }
        let index = self.count;
        let mut node = history_leaf_hash(Some(leaf));
        let mut formed = alloc::vec![HistorySubtree {
            level: 0,
            start: index,
            root: node,
        }];
        for (level, left) in self
            .peaks
            .iter()
            .take(index.trailing_ones() as usize)
            .enumerate()
        {
            node = history_node_hash(level, *left, node);
            let height = level + 1;
            formed.push(HistorySubtree {
                level: level_byte(height),
                start: index >> height << height,
                root: node,
            });
        }
        Some(formed)
    }

    /// The current opening of occupied position `index`, taking each complete
    /// sibling from `subtree(level, start)`. A partially occupied sibling holds
    /// the next empty position and comes from this frontier; empty siblings
    /// are constants. `Ok(None)` when `subtree` lacks a sibling, `index` is not
    /// occupied or the frontier is malformed.
    ///
    /// # Errors
    /// Returns the first error `subtree` reports.
    pub fn open<E>(
        &self,
        index: u64,
        mut subtree: impl FnMut(u8, u64) -> Result<Option<Hash>, E>,
    ) -> Result<Option<HistoryPath>, E> {
        if index >= self.count || self.peaks.len() != self.count.count_ones() as usize {
            return Ok(None);
        }
        let empty = &EMPTY_HISTORY_HASHES;
        // `partial[level]` roots the level subtree holding the next empty position.
        let mut partial = Vec::with_capacity(HISTORY_DEPTH);
        let mut peaks = self.peaks.iter();
        let mut right = empty[0];
        for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
            partial.push(right);
            right = if (self.count >> level) & 1 == 1 {
                let Some(peak) = peaks.next() else {
                    return Ok(None);
                };
                history_node_hash(level, *peak, right)
            } else {
                history_node_hash(level, right, *empty_subtree)
            };
        }
        let mut siblings = Vec::with_capacity(HISTORY_DEPTH);
        for (level, partial_root) in partial.into_iter().enumerate() {
            let start = ((index >> level) ^ 1) << level;
            let sibling = if start >= self.count {
                empty[level]
            } else if subtree_complete(level, start, self.count) {
                let Some(root) = subtree(level_byte(level), start)? else {
                    return Ok(None);
                };
                root
            } else {
                partial_root
            };
            siblings.push(sibling);
        }
        Ok(Some(HistoryPath {
            index,
            count: self.count,
            siblings,
        }))
    }
}
