use super::*;
use neutrin0_consensus_types::{AggregatedVote, FinalityVotePhase};
use neutrin0_consensus_types::{Chunk, FinalityCert, Header};
use neutrin0_primitives::BitVec;

fn hash(byte: u8) -> Hash {
    [byte; 32]
}

fn header(parent_hash: BlockHash, height: Height, proposer_index: ValidatorIndex) -> Header {
    Header {
        height,
        slot: height,
        parent_hash,
        proposer_index,
        vrf_proof: [u8::try_from(proposer_index).expect("small test proposer"); 96],
        state_root: hash(1),
        transactions_root: hash(2),
        votes_root: hash(3),
        da_root: hash(6),
        runtime_extra: hash(7),
        inputs_root: [0; 32],
        receipts_root: hash(11),
        gas_used: 8,
        gas_limit: 9,
        timestamp: 10,
        signature: [0xAA; 96],
    }
}

#[test]
fn stale_subtrees_reach_every_descendant() {
    let finalized = hash(0);
    let mut fork_choice = ForkChoice::new(finalized);
    let first = fork_choice.add_block(&header(finalized, 1, 1)).unwrap();
    let child = fork_choice.add_block(&header(first, 2, 2)).unwrap();
    let mut sibling_header = header(finalized, 1, 3);
    sibling_header.slot = 5;
    let sibling = fork_choice.add_block(&sibling_header).unwrap();
    fork_choice
        .on_block_proof(child, ProofStatus::Proven)
        .unwrap();
    assert_eq!(fork_choice.block_at_slot(1, 1), Some(first));
    assert_eq!(fork_choice.block_at_slot(1, 2), None);
    assert_eq!(fork_choice.unproven_count(), 2);
    // The later sibling shares `first`'s window, so both go stale together.
    assert_eq!(fork_choice.mark_stale(1), 2);
    assert_eq!(fork_choice.unproven_count(), 2);
    // A proven descendant of a stale block goes with it.
    let removed = fork_choice.stale_subtrees(1);
    assert_eq!(removed, [first, child, sibling].into_iter().collect());
    fork_choice.remove_blocks(&removed);
    assert!(fork_choice.block(&first).is_none());
    assert!(fork_choice.block(&child).is_none());
    assert!(fork_choice.block(&sibling).is_none());
    assert_eq!(fork_choice.head(), finalized);
}

fn chunk(end_block_hash: BlockHash, chunk_id: u64) -> Chunk {
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id,
        start_height: 1,
        end_height: 1,
        start_state_root: hash(11),
        end_state_root: hash(12),
        start_block_hash: end_block_hash,
        end_block_hash,
        block_hash_root: hash(13),
        block_proof_root: hash(14),
        vrf_proof_root: hash(15),
        active_validator_set_root: hash(16),
        next_validator_set_root: hash(17),
        da_root: hash(18),
    }
}

fn vote(chunk: &Chunk, weight: u128) -> ChunkVote {
    ChunkVote {
        data: FinalityVoteData {
            chunk_id: chunk.chunk_id,
            round: 0,
            chunk_hash: chunk.hash(),
            selection: [0; 32],
            phase: FinalityVotePhase::Prevote,
        },
        weight,
    }
}

fn cert(chunk: &Chunk) -> FinalityCert {
    FinalityCert {
        proposal: neutrin0_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round: 0,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            proposal_slot: 0,
            receipts: Vec::new(),
            ratified_chunk_proofs: Vec::new(),
            signature: [0; 96],
        },
        prevote_attestations: Vec::new(),
        precommit_attestations: Vec::new(),
        proof_manifests: Vec::new(),
        chunk_id: chunk.chunk_id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: AggregatedVote {
            aggregation_bits: BitVec::default(),
            signature: [0xBB; 96],
        },
        precommit: AggregatedVote {
            aggregation_bits: BitVec::default(),
            signature: [0xCC; 96],
        },
        active_validator_set_root: chunk.active_validator_set_root,
    }
}

#[test]
fn pending_blocks_are_tentative_heads() {
    let mut fork_choice = ForkChoice::default();
    let block = fork_choice
        .add_block(&header(ZERO_HASH, 1, 1))
        .expect("add block");

    assert_eq!(fork_choice.head(), block);
}

#[test]
fn votes_choose_heavier_branch() {
    let mut fork_choice = ForkChoice::default();
    let left = fork_choice
        .add_block(&header(ZERO_HASH, 1, 1))
        .expect("add left");
    let right = fork_choice
        .add_block(&header(ZERO_HASH, 1, 2))
        .expect("add right");
    let left_chunk = chunk(left, 1);
    let right_chunk = chunk(right, 2);
    fork_choice.add_chunk(&left_chunk);
    fork_choice.add_chunk(&right_chunk);

    fork_choice.add_vote(0, vote(&left_chunk, 10));
    fork_choice.add_vote(1, vote(&right_chunk, 30));

    assert_eq!(fork_choice.head(), right);
}

#[test]
fn latest_vote_replaces_older_vote() {
    let mut fork_choice = ForkChoice::default();
    let left = fork_choice
        .add_block(&header(ZERO_HASH, 1, 1))
        .expect("add left");
    let right = fork_choice
        .add_block(&header(ZERO_HASH, 1, 2))
        .expect("add right");
    let left_chunk = chunk(left, 1);
    let right_chunk = chunk(right, 2);
    fork_choice.add_chunk(&left_chunk);
    fork_choice.add_chunk(&right_chunk);

    fork_choice.add_vote(0, vote(&left_chunk, 10));
    assert_eq!(fork_choice.head(), left);
    fork_choice.add_vote(0, vote(&right_chunk, 10));

    assert_eq!(fork_choice.head(), right);
}

#[test]
fn finalization_moves_anchor_and_prunes_old_forks() {
    let mut fork_choice = ForkChoice::default();
    let finalized_child = fork_choice
        .add_block(&header(ZERO_HASH, 1, 1))
        .expect("add finalized child");
    let descendant = fork_choice
        .add_block(&header(finalized_child, 2, 2))
        .expect("add descendant");
    let old_fork = fork_choice
        .add_block(&header(ZERO_HASH, 1, 3))
        .expect("add old fork");
    let finalized_chunk = chunk(finalized_child, 1);

    fork_choice
        .add_finalized_chunk(&finalized_chunk, &cert(&finalized_chunk))
        .expect("finalize chunk");

    assert_eq!(fork_choice.finalized(), finalized_child);
    assert_eq!(fork_choice.head(), descendant);
    assert!(!fork_choice.block_extends(old_fork, fork_choice.finalized()));
}

fn status(tree: &ForkChoice, hash: &BlockHash) -> ProofStatus {
    tree.block(hash).expect("known block").proof_status
}

#[test]
fn finalization_marks_only_the_segment_above_the_previous_anchor() {
    let mut tree = ForkChoice::default();
    let mut chain = Vec::new();
    let mut parent = ZERO_HASH;
    for height in 1..=4 {
        let child = header(parent, height, 1);
        parent = tree.add_block(&child).expect("add chain block");
        chain.push(parent);
    }
    let first = chunk(chain[1], 0);
    tree.add_finalized_chunk(&first, &cert(&first))
        .expect("finalize first chunk");
    for block in &chain[..2] {
        assert_eq!(status(&tree, block), ProofStatus::Finalized);
    }
    // Without pruning the old anchor and its ancestors stay known. Distinct
    // statuses on them reveal any walk past the previous anchor.
    for block in &chain[..2] {
        tree.on_block_proof(*block, ProofStatus::Proven).unwrap();
    }
    let second = chunk(chain[3], 1);
    tree.add_finalized_chunk(&second, &cert(&second))
        .expect("finalize second chunk");
    assert_eq!(tree.finalized(), chain[3]);
    for block in &chain[2..] {
        assert_eq!(status(&tree, block), ProofStatus::Finalized);
    }
    for block in &chain[..2] {
        assert_eq!(status(&tree, block), ProofStatus::Proven);
    }
    // Finalizing the current anchor again walks nothing.
    let anchor = chain[3];
    tree.on_block_proof(anchor, ProofStatus::Proven).unwrap();
    tree.add_finalized_chunk(&second, &cert(&second))
        .expect("refinalize anchor");
    assert_eq!(status(&tree, &anchor), ProofStatus::Proven);
}

#[test]
fn rejects_unknown_parent_and_unknown_proof_update() {
    let mut fork_choice = ForkChoice::default();
    assert_eq!(
        fork_choice.add_block(&header(hash(99), 1, 1)),
        Err(ForkChoiceError::UnknownParent(hash(99)))
    );
    assert_eq!(
        fork_choice.on_block_proof(hash(88), ProofStatus::Proven),
        Err(ForkChoiceError::UnknownBlock(hash(88)))
    );
}
#[test]
fn pruning_preserves_live_descendant_votes() {
    let mut tree = ForkChoice::default();
    let first = tree.add_block(&header(ZERO_HASH, 1, 1)).unwrap();
    let detached = tree.add_block(&header(ZERO_HASH, 1, 2)).unwrap();
    let live = tree.add_block(&header(first, 2, 1)).unwrap();
    let retired_chunk = chunk(detached, 1);
    let live_chunk = chunk(live, 2);
    tree.add_chunk(&retired_chunk);
    tree.add_chunk(&live_chunk);
    tree.add_vote(0, vote(&retired_chunk, 10));
    tree.add_vote(1, vote(&live_chunk, 30));
    let finalized = chunk(first, 0);
    tree.add_finalized_chunk(&finalized, &cert(&finalized))
        .unwrap();
    let before = tree.head();
    tree.retain_finalized_subtree();
    assert_eq!(tree.head(), before);
    assert!(tree.block(&first).is_none());
    assert!(tree.block(&detached).is_none());
    assert!(tree.block(&live).is_some());
    assert_eq!(tree.vote_count(), 1);
    tree.retain_finalized_subtree();
    assert_eq!(tree.head(), live);
}

/// Deterministic SplitMix64 stream for generated fork-choice states.
struct TestRng(u64);

impl TestRng {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

fn assert_matches_reference(tree: &ForkChoice, stage: &str) {
    assert_eq!(tree.head(), tree.head_reference(), "{stage}");
}

#[test]
fn single_walk_head_matches_the_per_vote_reference_on_varied_dags() {
    let statuses = [
        ProofStatus::PendingProof,
        ProofStatus::Proven,
        ProofStatus::Stale,
        ProofStatus::Finalized,
    ];
    let mut rng = TestRng(0x6E65_7574_7269_6E6F);
    let (mut moved_heads, mut overflows) = (0_usize, 0_usize);
    for case in 0..300_u64 {
        let mut tree = ForkChoice::new(hash(u8::try_from(case % 3).unwrap()));
        let mut blocks = Vec::new();
        for index in 0..=rng.below(24) {
            let parent = if blocks.is_empty() || rng.below(5) == 0 {
                tree.finalized()
            } else {
                rng.pick(&blocks)
            };
            let proposer = u32::try_from(rng.below(4)).unwrap();
            let mut block_header = header(parent, 1 + rng.next_u64() % 20, proposer);
            block_header.timestamp = u64::try_from(index).unwrap();
            let block = tree.add_block(&block_header).unwrap();
            let status = rng.pick(&statuses);
            tree.on_block_proof(block, status).unwrap();
            blocks.push(block);
        }
        for validator in 0..u32::try_from(rng.below(12)).unwrap() {
            let end = if rng.below(6) == 0 {
                hash(200)
            } else {
                rng.pick(&blocks)
            };
            let target = chunk(end, rng.next_u64() % 4);
            if rng.below(4) != 0 {
                tree.add_chunk(&target);
            }
            let weight = match rng.below(8) {
                0 => u128::MAX,
                1 => u128::MAX / 2,
                _ => u128::from(rng.next_u64() % 100),
            };
            tree.add_vote(validator, vote(&target, weight));
        }
        assert_matches_reference(&tree, &format!("case {case} before finality"));
        for block in &blocks {
            if tree.score_candidate(*block) == Err(ForkChoiceError::ScoreOverflow) {
                overflows += 1;
            }
        }

        let target = rng.pick(&blocks);
        match rng.below(3) {
            0 if tree.block_extends(target, tree.finalized()) => {
                let finalized = chunk(target, 99);
                let result = tree.add_finalized_chunk(&finalized, &cert(&finalized));
                assert_eq!(result, Ok(()));
            }
            1 => tree.finalized = hash(250),
            _ => tree.finalized = target,
        }
        assert_matches_reference(&tree, &format!("case {case} after finality"));
        if tree.head() != tree.finalized() {
            moved_heads += 1;
        }
        tree.retain_finalized_subtree();
        assert_matches_reference(&tree, &format!("case {case} after pruning"));
    }
    assert!(moved_heads > 0, "generated states never chose a block head");
    assert!(overflows > 0, "generated states never overflowed a score");
}

#[test]
fn stale_candidates_leave_head_selection_until_proven() {
    let genesis = hash(0);
    let mut fc = ForkChoice::new(genesis);
    let a = fc.add_block(&header(genesis, 1, 0)).unwrap();
    let b = fc.add_block(&header(a, 2, 1)).unwrap();
    assert_eq!(fc.head(), b);
    // `a` (slot 1) passes its window; `b` (slot 2) is excluded through it.
    assert_eq!(fc.mark_stale(1), 1);
    assert_eq!(fc.head(), genesis);
    assert!(fc.on_stale_branch(b) && !fc.on_stale_branch(genesis));
    assert_eq!(fc.mark_stale(1), 0, "marking is idempotent");
    // A receipt restores the branch.
    fc.on_block_proof(a, ProofStatus::Proven).unwrap();
    assert_eq!(fc.head(), b);
    assert!(!fc.on_stale_branch(b));
    assert_eq!(fc.mark_stale(2), 1);
    assert_eq!(fc.head(), a);
    assert!(fc.on_stale_branch(b) && !fc.on_stale_branch(a));
    assert_eq!(fc.block(&b).unwrap().proof_status, ProofStatus::Stale);
}

#[test]
fn single_walk_head_matches_the_reference_through_self_parented_blocks() {
    let looped = hash(77);
    let node = BlockNode {
        hash: looped,
        parent_hash: looped,
        height: 1,
        slot: 1,
        stale_clock: 1,
        proposer_index: 0,
        proof_status: ProofStatus::Proven,
        vrf_tie_breaker: hash(5),
    };
    let mut tree = ForkChoice::default();
    tree.blocks.insert(looped, node);
    let child = tree.add_block(&header(looped, 2, 1)).unwrap();
    let grandchild = tree.add_block(&header(child, 3, 2)).unwrap();
    let sibling = tree.add_block(&header(looped, 2, 3)).unwrap();
    let rooted = tree.add_block(&header(ZERO_HASH, 1, 1)).unwrap();
    for (block, weight) in [(looped, 5), (child, 7), (grandchild, 1), (rooted, 4)] {
        let target = chunk(block, weight);
        tree.add_chunk(&target);
        tree.add_vote(
            u32::try_from(weight).unwrap(),
            vote(&target, u128::from(weight)),
        );
    }
    for (finalized, stale) in [
        (ZERO_HASH, None),
        (looped, None),
        (looped, Some(sibling)),
        (child, Some(looped)),
    ] {
        for block in [looped, child, grandchild, sibling, rooted] {
            tree.on_block_proof(block, ProofStatus::Proven).unwrap();
        }
        if let Some(block) = stale {
            tree.on_block_proof(block, ProofStatus::Stale).unwrap();
        }
        tree.finalized = finalized;
        assert_matches_reference(&tree, &format!("finalized {finalized:?}"));
    }
}

#[test]
fn a_proven_branch_outranks_a_higher_unproven_one_and_siblings_share_a_window() {
    let genesis = hash(0);
    let mut fc = ForkChoice::new(genesis);
    let a = fc.add_block(&header(genesis, 1, 1)).unwrap();
    let b = fc.add_block(&header(a, 2, 2)).unwrap();
    // A sibling of `a` signed much later inherits `a`'s window.
    let mut late = header(genesis, 1, 20);
    late.slot = 20;
    let a2 = fc.add_block(&late).unwrap();
    assert_eq!(fc.block(&a2).unwrap().stale_clock, 1);
    assert_eq!(fc.head(), b);
    // Once `a2` is proven its branch wins over the longer unproven one.
    fc.on_block_proof(a2, ProofStatus::Proven).unwrap();
    assert_eq!(fc.head(), a2);
    assert_eq!(fc.head(), fc.head_reference());
    // `a`'s window passing stales `a` and `b`, but not the proven sibling.
    assert_eq!(fc.mark_stale(1), 1);
    assert_eq!(
        fc.block(&b).unwrap().proof_status,
        ProofStatus::PendingProof
    );
    assert_eq!(fc.head(), a2);
}
