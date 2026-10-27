//! Membership openings of occupied History positions.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_primitives::Hash;

use super::{
    EMPTY_HISTORY_HASHES, HISTORY_DEPTH, HistoryFrontier, HistorySubtree, counted_history_root,
    history_leaf_hash, history_node_hash, level_byte, subtree_complete,
};

/// Membership of one exact occupied historical index under a counted root.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct HistoryPath {
    /// Chunk ID, strictly below the authenticated count.
    pub index: u64,
    /// Number of consecutive occupied historical records.
    pub count: u64,
    /// Exactly 64 siblings, starting at leaf height.
    pub siblings: Vec<Hash>,
}

impl BorshDeserialize for HistoryPath {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let index = u64::deserialize_reader(reader)?;
        let count = u64::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)?;
        if index >= count || length != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history path shape",
            ));
        }
        let siblings = (0..length)
            .map(|_| Hash::deserialize_reader(reader))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            index,
            count,
            siblings,
        })
    }
}

impl HistoryPath {
    /// Build an opening from archived contexts.
    #[must_use]
    pub fn build(leaves: &[Hash], index: usize) -> Option<Self> {
        if index >= leaves.len() {
            return None;
        }
        let count = u64::try_from(leaves.len()).ok()?;
        let empty = &EMPTY_HISTORY_HASHES;
        let mut nodes: Vec<_> = leaves
            .iter()
            .map(|leaf| history_leaf_hash(Some(*leaf)))
            .collect();
        let mut position = index;
        let mut siblings = Vec::with_capacity(HISTORY_DEPTH);
        for (level, empty_subtree) in empty.iter().enumerate().take(HISTORY_DEPTH) {
            siblings.push(nodes.get(position ^ 1).copied().unwrap_or(*empty_subtree));
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    history_node_hash(
                        level,
                        pair[0],
                        pair.get(1).copied().unwrap_or(*empty_subtree),
                    )
                })
                .collect();
            position /= 2;
        }
        Some(Self {
            index: u64::try_from(index).ok()?,
            count,
            siblings,
        })
    }

    /// Verify membership, count, exact depth and occupied-leaf encoding.
    #[must_use]
    pub fn verify(&self, leaf: Hash, expected: Hash) -> bool {
        if self.index >= self.count || self.siblings.len() != HISTORY_DEPTH {
            return false;
        }
        let mut node = history_leaf_hash(Some(leaf));
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if (self.index >> level) & 1 == 0 {
                history_node_hash(level, node, *sibling)
            } else {
                history_node_hash(level, *sibling, node)
            };
        }
        counted_history_root(self.count, node) == expected
    }

    /// Authenticate and advance this opening over one finalized append.
    /// Only the sibling shared with the appended leaf changes. Returns the new
    /// counted root; invalid inputs or exhausted indexes leave the path unchanged.
    pub fn advance(
        &mut self,
        leaf: Hash,
        frontier: &HistoryFrontier,
        appended_leaf: Hash,
    ) -> Option<Hash> {
        if self.count != frontier.count || !self.verify(leaf, frontier.root()?) {
            return None;
        }
        let insertion = frontier.append_path(appended_leaf)?;
        // Membership above guarantees index < count, so the xor is nonzero.
        let changed_level = usize::try_from((self.index ^ frontier.count).ilog2()).ok()?;
        let mut sibling = history_leaf_hash(Some(appended_leaf));
        for (level, other) in insertion.siblings.iter().take(changed_level).enumerate() {
            sibling = if (frontier.count >> level) & 1 == 0 {
                history_node_hash(level, sibling, *other)
            } else {
                history_node_hash(level, *other, sibling)
            };
        }
        let mut next_frontier = frontier.clone();
        let root = next_frontier.append(appended_leaf)?;
        let mut next_path = self.clone();
        next_path.siblings[changed_level] = sibling;
        next_path.count = insertion.count;
        if !next_path.verify(leaf, root) {
            return None;
        }
        *self = next_path;
        Some(root)
    }
}

impl HistoryPath {
    /// The complete siblings of this opening. Together with the right siblings
    /// later appends complete, they open the same leaf at any later count.
    #[must_use]
    pub fn complete_siblings(&self) -> Vec<HistorySubtree> {
        self.siblings
            .iter()
            .enumerate()
            .take(HISTORY_DEPTH)
            .filter_map(|(level, sibling)| {
                let start = ((self.index >> level) ^ 1) << level;
                (start < self.count && subtree_complete(level, start, self.count)).then(|| {
                    HistorySubtree {
                        level: level_byte(level),
                        start,
                        root: *sibling,
                    }
                })
            })
            .collect()
    }
}
