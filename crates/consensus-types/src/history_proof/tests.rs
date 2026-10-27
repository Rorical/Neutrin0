use super::*;
use crate::history::{HistoryFrontier, HistoryPath, history_root};
use alloc::vec;
use neutrin0_primitives::{
    ConsensusParams, LightClientParams, ProofParams, RuntimeInfo, RuntimeParams,
};

fn spec() -> ChainSpec {
    ChainSpec {
        name: BoundedBytes::new(b"anchors".to_vec()).unwrap(),
        chain_id: 7,
        genesis_time: 0,
        genesis_gas_limit: 1,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [4; 32],
        genesis_execution: ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [5; 32],
        genesis_state_root: [2; 32],
        genesis_block_hash: [1; 32],
        genesis_validator_set_root: [3; 32],
        consensus: ConsensusParams::default(),
        proof: ProofParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: Vec::new(),
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

fn context(chunk_id: u64, start: &ConsensusBoundary) -> EvidenceContext {
    EvidenceContext {
        chunk_id,
        chunk_hash: [chunk_id as u8; 32],
        end_height: chunk_id + 1,
        validators_root: [3; 32],
        seed: [5; 32],
        source_block_guest_vk_digest: [3; 8],
        source_runtime_code_hash: [4; 32],
        start_boundary: start.commitment(),
    }
}

/// Genesis plus three boundaries whose history roots commit every
/// earlier chunk's start boundary, as the chunk Guest appends them.
fn chain(spec: &ChainSpec) -> (Vec<ConsensusBoundary>, Vec<EvidenceContext>) {
    let mut boundaries = vec![ConsensusBoundary::genesis(spec)];
    let mut contexts = Vec::new();
    let mut frontier = HistoryFrontier::empty();
    for id in 0..3_u64 {
        let start = boundaries[id as usize];
        let leaf = context(id, &start);
        contexts.push(leaf);
        let history_root = frontier.append(crate::evidence::commitment(&leaf)).unwrap();
        boundaries.push(ConsensusBoundary {
            next_chunk_id: id + 1,
            height: id + 1,
            block_hash: [id as u8 + 10; 32],
            history_root,
            ..start
        });
    }
    (boundaries, contexts)
}

fn opening(contexts: &[EvidenceContext], index: usize, count: usize) -> AnchorOpening {
    let leaves: Vec<_> = contexts[..count]
        .iter()
        .map(crate::evidence::commitment)
        .collect();
    assert_eq!(history_root(&leaves), chain(&spec()).0[count].history_root);
    AnchorOpening {
        context: contexts[index],
        path: HistoryPath::build(&leaves, index).unwrap(),
    }
}

#[test]
fn a_fork_start_is_trusted_like_genesis_and_nothing_below_it_anchors() {
    let spec = spec();
    let (boundaries, contexts) = chain(&spec);
    // Fork at count 1: the start is boundary 1 rebased onto the spec.
    let start = ConsensusBoundary::fork_start(&boundaries[1], &spec);
    assert_eq!(start.programs, spec.genesis_programs());
    assert!(anchors(&start, &start, &boundaries[3], None));
    assert!(!anchors(&start, &boundaries[0], &boundaries[3], None));
    let other = ConsensusBoundary {
        seed: [9; 32],
        ..start
    };
    assert!(!anchors(&start, &other, &boundaries[3], None));
    // Its leaf has an opening, but the start takes none: a provider
    // following `needs_opening` sends what `check_anchor` accepts.
    assert!(!needs_opening(start.next_chunk_id, start.next_chunk_id, 3));
    assert_eq!(
        check_anchor(
            &start,
            &start,
            &boundaries[3],
            Some(&opening(&contexts, 1, 3))
        ),
        AnchorCheck::Invalid
    );
    assert!(needs_opening(start.next_chunk_id, 2, 3));
    // A later anchor still needs its opening.
    assert!(anchors(
        &start,
        &boundaries[2],
        &boundaries[3],
        Some(&opening(&contexts, 2, 3))
    ));
}

#[test]
fn genesis_and_the_end_itself_need_no_opening() {
    let spec = spec();
    let (boundaries, contexts) = chain(&spec);
    assert!(anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[0],
        &boundaries[3],
        None
    ));
    assert!(anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[3],
        &boundaries[3],
        None
    ));
    assert!(!anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[3],
        &boundaries[3],
        Some(&opening(&contexts, 2, 3))
    ));
    let forged_genesis = ConsensusBoundary {
        seed: [9; 32],
        ..boundaries[0]
    };
    assert!(!anchors(
        &ConsensusBoundary::first(&spec),
        &forged_genesis,
        &boundaries[3],
        None
    ));
}

#[test]
fn an_intermediate_anchor_needs_the_opening_of_its_own_leaf() {
    let spec = spec();
    let (boundaries, contexts) = chain(&spec);
    let opened = opening(&contexts, 1, 3);
    assert!(anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[1],
        &boundaries[3],
        Some(&opened)
    ));
    assert!(!anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[1],
        &boundaries[3],
        None
    ));
    // Another chunk's leaf, a different anchor and a later anchor fail.
    assert!(!anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[1],
        &boundaries[3],
        Some(&opening(&contexts, 2, 3))
    ));
    let forged = ConsensusBoundary {
        state_root: [8; 32],
        ..boundaries[1]
    };
    assert!(!anchors(
        &ConsensusBoundary::first(&spec),
        &forged,
        &boundaries[3],
        Some(&opened)
    ));
    assert!(!anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[3],
        &boundaries[1],
        None
    ));
    // The opening must target exactly the end's leaf count.
    assert!(!anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[1],
        &boundaries[2],
        Some(&opened)
    ));
    assert!(anchors(
        &ConsensusBoundary::first(&spec),
        &boundaries[1],
        &boundaries[2],
        Some(&opening(&contexts, 1, 2))
    ));
}

#[test]
fn anchor_checks_separate_provider_faults_from_a_conflicting_chain() {
    let spec = spec();
    let genesis = ConsensusBoundary::first(&spec);
    let (boundaries, contexts) = chain(&spec);
    let opened = opening(&contexts, 1, 3);
    assert_eq!(
        check_anchor(&genesis, &boundaries[1], &boundaries[3], Some(&opened)),
        AnchorCheck::Extends
    );
    assert_eq!(
        check_anchor(&genesis, &boundaries[1], &boundaries[3], None),
        AnchorCheck::Unopened
    );
    // A path that does not verify is the provider's fault.
    let mut broken = opened.clone();
    broken.path.siblings[0][0] ^= 1;
    assert_eq!(
        check_anchor(&genesis, &boundaries[1], &boundaries[3], Some(&broken)),
        AnchorCheck::Invalid
    );
    // A verified leaf that started elsewhere places the anchor off the
    // proven chain.
    let ours = ConsensusBoundary {
        state_root: [8; 32],
        ..boundaries[1]
    };
    assert_eq!(
        check_anchor(&genesis, &ours, &boundaries[3], Some(&opened)),
        AnchorCheck::Conflicts
    );
    // So does a different endpoint at the anchor's own count.
    assert_eq!(
        check_anchor(&genesis, &ours, &boundaries[1], None),
        AnchorCheck::Conflicts
    );
    assert_eq!(
        check_anchor(&genesis, &boundaries[1], &boundaries[1], Some(&opened)),
        AnchorCheck::Invalid
    );
}
