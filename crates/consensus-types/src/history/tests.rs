use super::*;
use alloc::vec::Vec;

fn tagged(parts: &[&[u8]]) -> Hash {
    blake3_256(&parts.concat())
}

#[test]
fn appended_and_revealed_subtrees_open_every_leaf_like_a_full_rebuild() {
    let leaves: Vec<Hash> = (0_u8..41).map(|byte| [byte; 32]).collect();
    let mut frontier = HistoryFrontier::empty();
    let mut subtrees = alloc::collections::BTreeMap::new();
    // A store that starts watching leaf 5 at count 20 keeps that opening's
    // complete siblings, then each right child whose left neighbour holds 5.
    let mut watched = alloc::collections::BTreeMap::new();
    for (index, leaf) in leaves.iter().enumerate() {
        for formed in frontier.completed_subtrees(*leaf).unwrap() {
            subtrees.insert((formed.level, formed.start), formed.root);
            let width = 1_u64 << formed.level;
            if index >= 20
                && formed.start & width != 0
                && (formed.start - width..formed.start).contains(&5)
            {
                watched.insert((formed.level, formed.start), formed.root);
            }
        }
        frontier.append(*leaf).unwrap();
        if index == 19 {
            let opening = HistoryPath::build(&leaves[..20], 5).unwrap();
            for sibling in opening.complete_siblings() {
                assert_eq!(
                    subtrees.get(&(sibling.level, sibling.start)),
                    Some(&sibling.root)
                );
                watched.insert((sibling.level, sibling.start), sibling.root);
            }
        }
    }
    let root = frontier.root().unwrap();
    for (index, leaf) in leaves.iter().enumerate() {
        let opened = frontier
            .open(u64::try_from(index).unwrap(), |level, start| {
                Ok::<_, ()>(subtrees.get(&(level, start)).copied())
            })
            .unwrap()
            .unwrap();
        assert_eq!(opened, HistoryPath::build(&leaves, index).unwrap());
        assert!(opened.verify(*leaf, root));
    }
    let lookup = |level, start| Ok::<_, ()>(watched.get(&(level, start)).copied());
    let opened = frontier.open(5, lookup).unwrap().unwrap();
    assert!(opened.verify(leaves[5], root));
    // Leaf 2 was never watched, so its siblings were never kept.
    assert_eq!(frontier.open(2, lookup), Ok(None));
    assert_eq!(frontier.open(41, lookup), Ok(None));
}

#[test]
fn generated_empty_hashes_match_the_recursive_definition() {
    let mut empty = [[0; 32]; HISTORY_DEPTH + 1];
    empty[0] = history_leaf_hash(None);
    for level in 0..HISTORY_DEPTH {
        empty[level + 1] = history_node_hash(level, empty[level], empty[level]);
    }
    assert_eq!(EMPTY_HISTORY_HASHES, empty);
    assert_eq!(empty_history_hashes(), empty);
    assert_eq!(
        EMPTY_HISTORY_ROOT,
        counted_history_root(0, empty[HISTORY_DEPTH])
    );
    assert_eq!(empty_history_root(), EMPTY_HISTORY_ROOT);
    assert_eq!(HistoryFrontier::empty().root(), Some(EMPTY_HISTORY_ROOT));
}

#[test]
fn fixed_preimages_match_tagged_concatenation() {
    let (left, right) = ([7; 32], [9; 32]);
    assert_eq!(
        history_leaf_hash(None),
        tagged(&[&DOMAIN_HISTORY_LEAF, &[0]])
    );
    assert_eq!(
        history_leaf_hash(Some(left)),
        tagged(&[&DOMAIN_HISTORY_LEAF, &[1], &left])
    );
    for level in [0, 1, HISTORY_DEPTH - 1] {
        assert_eq!(
            history_node_hash(level, left, right),
            tagged(&[
                &DOMAIN_HISTORY_NODE,
                &[u8::try_from(level).unwrap()],
                &left,
                &right,
            ])
        );
    }
    for count in [0, 5, u64::MAX] {
        assert_eq!(
            counted_history_root(count, left),
            tagged(&[&DOMAIN_HISTORY_ROOT, &count.to_le_bytes(), &left])
        );
    }
}

#[test]
fn recent_history_window_has_exact_inclusive_lower_bound() {
    assert!(!is_recent_history_index(0, 0));
    for count in [1, 7, 8, 9, 10_000, u64::MAX] {
        let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
        assert!(is_recent_history_index(first, count));
        assert!(is_recent_history_index(count - 1, count));
        assert!(!is_recent_history_index(count, count));
        if first > 0 {
            assert!(!is_recent_history_index(first - 1, count));
        }
    }
}

#[test]
fn history_record_window_covers_one_unbonding_delay_of_records() {
    // 1,152 blocks of 128-block chunks: nine chunks.
    assert_eq!(history_record_window_chunks(1_152, 128), 9);
    // Fourteen days of 4 s slots at the default chunk size.
    assert_eq!(history_record_window_chunks(302_400, 128), 2_363);
    // A delay shorter than eight chunks never shrinks ordinary retention.
    assert_eq!(
        history_record_window_chunks(1, 128),
        HISTORY_RETENTION_CHUNKS
    );
    assert_eq!(
        history_record_window_chunks(10, 0),
        HISTORY_RETENTION_CHUNKS
    );
    assert!(is_history_index_within(0, 9, 9));
    assert!(!is_history_index_within(0, 10, 9));
    assert!(!is_history_index_within(10, 10, 9));
}

#[test]
fn append_and_paths_match_at_power_of_two_boundaries() {
    let mut leaves = Vec::new();
    let mut frontier = HistoryFrontier::empty();
    assert_eq!(frontier.root(), Some(empty_history_root()));
    for index in 0_u64..260 {
        let positions = [
            0,
            leaves.len() / 3,
            leaves.len() / 2,
            leaves.len().saturating_sub(1),
        ];
        let paths: Vec<_> = positions
            .into_iter()
            .filter_map(|position| {
                HistoryPath::build(&leaves, position).map(|path| (position, path))
            })
            .collect();
        let before = frontier.clone();
        leaves.push(blake3_256(&index.to_le_bytes()));
        let appended_leaf = *leaves.last().unwrap();
        let insertion = frontier.append_path(appended_leaf).unwrap();
        assert_eq!(frontier, before);
        let root = frontier.append(appended_leaf).unwrap();
        assert_eq!(
            insertion,
            HistoryPath::build(&leaves, leaves.len() - 1).unwrap()
        );
        assert!(insertion.verify(appended_leaf, root));
        for (position, mut path) in paths {
            let prior_siblings = path.siblings.clone();
            let changed_level = usize::try_from((path.index ^ before.count).ilog2()).unwrap();
            assert_eq!(
                path.advance(leaves[position], &before, appended_leaf),
                Some(root)
            );
            assert_eq!(path, HistoryPath::build(&leaves, position).unwrap());
            for (level, sibling) in prior_siblings.iter().enumerate() {
                if level != changed_level {
                    assert_eq!(path.siblings[level], *sibling);
                }
            }
        }
        for position in [0, leaves.len() / 2, leaves.len() - 1] {
            let path = HistoryPath::build(&leaves, position).unwrap();
            assert!(path.verify(leaves[position], root));
            assert_eq!(path.siblings.len(), HISTORY_DEPTH);
        }
        assert!(frontier.peaks.len() <= HISTORY_DEPTH);
    }
}

#[test]
fn cached_old_paths_advance_without_archived_leaves() {
    let mut frontier = HistoryFrontier::empty();
    let mut retained = Vec::new();
    for index in 0_u64..260 {
        let leaf = blake3_256(&index.to_le_bytes());
        let insertion = frontier.append_path(leaf).unwrap();
        for (retained_leaf, path) in &mut retained {
            assert!(HistoryPath::advance(path, *retained_leaf, &frontier, leaf).is_some());
        }
        let root = frontier.append(leaf).unwrap();
        if index == 0 || index.is_power_of_two() || index == 259 {
            retained.push((leaf, insertion));
        }
        for (retained_leaf, path) in &retained {
            assert!(path.verify(*retained_leaf, root));
        }
    }
    assert_eq!(retained.first().unwrap().1.index, 0);
    assert_eq!(retained.first().unwrap().1.count, 260);
}

#[test]
fn malformed_count_paths_and_frontiers_fail_closed() {
    let leaves = [[7; 32], [8; 32], [9; 32]];
    let root = history_root(&leaves);
    let path = HistoryPath::build(&leaves, 1).unwrap();
    let mut wrong = path.clone();
    wrong.count += 1;
    assert!(!wrong.verify(leaves[1], root));
    let mut wrong = path.clone();
    wrong.index = 2;
    assert!(!wrong.verify(leaves[1], root));
    let mut wrong = path.clone();
    wrong.siblings.pop();
    assert!(!wrong.verify(leaves[1], root));
    assert!(borsh::from_slice::<HistoryPath>(&borsh::to_vec(&wrong).unwrap()).is_err());
    let mut wrong = path;
    wrong.siblings[63][0] ^= 1;
    assert!(!wrong.verify(leaves[1], root));
    let mut frontier = HistoryFrontier {
        count: 3,
        peaks: Vec::new(),
    };
    assert!(frontier.root().is_none());
    assert!(frontier.append([1; 32]).is_none());
    assert_eq!(frontier.count, 3);
    assert!(borsh::from_slice::<HistoryFrontier>(&borsh::to_vec(&frontier).unwrap()).is_err());
}

#[test]
fn invalid_path_advancement_never_mutates() {
    let leaves = [[7; 32], [8; 32], [9; 32]];
    let frontier = HistoryFrontier::from_leaves(&leaves).unwrap();
    let path = HistoryPath::build(&leaves, 1).unwrap();
    let mut malformed_paths = Vec::new();
    let mut wrong = path.clone();
    wrong.count += 1;
    malformed_paths.push(wrong);
    let mut wrong = path.clone();
    wrong.index = wrong.count;
    malformed_paths.push(wrong);
    let mut wrong = path.clone();
    wrong.index = 0;
    malformed_paths.push(wrong);
    let mut wrong = path.clone();
    wrong.siblings.pop();
    malformed_paths.push(wrong);
    let mut wrong = path.clone();
    wrong.siblings.push([0; 32]);
    malformed_paths.push(wrong);
    let mut wrong = path.clone();
    wrong.siblings[63][0] ^= 1;
    malformed_paths.push(wrong);
    for mut malformed in malformed_paths {
        let before = malformed.clone();
        assert!(malformed.advance(leaves[1], &frontier, [10; 32]).is_none());
        assert_eq!(malformed, before);
    }
    let mut wrong_leaf = path.clone();
    assert!(wrong_leaf.advance([0; 32], &frontier, [10; 32]).is_none());
    assert_eq!(wrong_leaf, path);
    let mut malformed_frontiers = Vec::new();
    let mut wrong = frontier.clone();
    wrong.peaks.pop();
    malformed_frontiers.push(wrong);
    let mut wrong = frontier.clone();
    wrong.peaks[0][0] ^= 1;
    malformed_frontiers.push(wrong);
    let mut wrong = frontier;
    wrong.count += 1;
    malformed_frontiers.push(wrong);
    for malformed in malformed_frontiers {
        let mut unchanged = path.clone();
        assert!(unchanged.advance(leaves[1], &malformed, [10; 32]).is_none());
        assert_eq!(unchanged, path);
    }
    let malformed = HistoryFrontier {
        count: 3,
        peaks: Vec::new(),
    };
    assert!(malformed.append_path([10; 32]).is_none());
}

#[test]
fn high_counts_keep_bounded_shape_and_overflow_does_not_mutate() {
    let empty = empty_history_hashes();
    for count in [1 << 32, (1 << 63) - 1, 1 << 63, u64::MAX - 1] {
        let mut frontier = HistoryFrontier {
            count,
            peaks: (0..HISTORY_DEPTH)
                .filter(|level| (count >> level) & 1 == 1)
                .map(|level| empty[level])
                .collect(),
        };
        let before = frontier.clone();
        let mut path = frontier.append_path([1; 32]).unwrap();
        assert_eq!(frontier, before);
        assert!(frontier.root().is_some());
        let root = frontier.append([1; 32]).unwrap();
        assert!(path.verify([1; 32], root));
        let path_before = path.clone();
        if frontier.count == u64::MAX {
            assert!(path.advance([1; 32], &frontier, [2; 32]).is_none());
            assert_eq!(path, path_before);
        } else {
            let next_root = path.advance([1; 32], &frontier, [2; 32]).unwrap();
            assert_eq!(frontier.append([2; 32]), Some(next_root));
            assert!(path.verify([1; 32], next_root));
        }
        assert!(frontier.peaks.len() <= HISTORY_DEPTH);
    }
    let mut full = HistoryFrontier {
        count: u64::MAX,
        peaks: alloc::vec![[1; 32]; 64],
    };
    let before = full.clone();
    assert!(full.append_path([2; 32]).is_none());
    assert!(full.append([2; 32]).is_none());
    assert_eq!(full, before);
    assert_ne!(history_leaf_hash(None), history_leaf_hash(Some([0; 32])));
}
