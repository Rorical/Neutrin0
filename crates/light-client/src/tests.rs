use super::*;
use alloc::vec::Vec;
use neutrin0_consensus_types::ChunkProofPublicInputs;
use neutrin0_consensus_types::evidence::{EvidenceContext, commitment};
use neutrin0_consensus_types::history::HistoryFrontier;
use neutrin0_consensus_types::history_proof::{ChunkReceiptStatement, ConsensusStatement};
use neutrin0_primitives::BoundedBytes;

struct Verifier(bool);
impl HistoryVerifier for Verifier {
    type Error = ();
    fn verify_history(&self, _: &HistoryProof, _: &VkDigest) -> Result<(), ()> {
        if self.0 { Ok(()) } else { Err(()) }
    }
}

const CHUNK: [u32; 8] = [4; 8];

fn spec() -> neutrin0_primitives::ChainSpec {
    use neutrin0_primitives::{
        ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo, RuntimeParams,
        Validator,
    };
    let validators = alloc::vec![Validator {
        pubkey: [1; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([2; 20]),
        effective_stake: 1,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }];
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(alloc::vec![]).unwrap(),
        chain_id: 1,
        genesis_time: 100,
        genesis_gas_limit: 1,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [2; 32],
        genesis_chunk: CHUNK,
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [4; 32],
        genesis_state_root: [2; 32],
        genesis_block_hash: [1; 32],
        genesis_validator_set_root: neutrin0_primitives::validators_root(&validators),
        consensus: ConsensusParams {
            slot_duration_secs: 10,
            chunk_size: 1,
            ..ConsensusParams::default()
        },
        proof: ProofParams::default(),
        light_client: LightClientParams {
            weak_subjectivity_period_secs: 100,
            stale_threshold_secs: 30,
        },
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(alloc::vec![]).unwrap(),
    }
}

fn chain_binding() -> ChainBinding {
    ChainBinding::new(&spec())
}

/// Genesis and the next three boundaries. Each history root commits every
/// earlier chunk's start boundary, as the chunk Guest appends them.
fn chain() -> (Vec<ConsensusBoundary>, Vec<EvidenceContext>) {
    let mut boundaries = alloc::vec![ConsensusBoundary::genesis(&spec())];
    let mut contexts = Vec::new();
    let mut frontier = HistoryFrontier::empty();
    for id in 0..3_u64 {
        let start = *boundaries.last().unwrap();
        let context = EvidenceContext {
            chunk_id: id,
            chunk_hash: [7; 32],
            end_height: id + 1,
            validators_root: start.validators_root,
            seed: start.seed,
            source_block_guest_vk_digest: [3; 8],
            source_runtime_code_hash: [2; 32],
            start_boundary: start.commitment(),
        };
        let history_root = frontier.append(commitment(&context)).unwrap();
        contexts.push(context);
        boundaries.push(ConsensusBoundary {
            next_chunk_id: id + 1,
            height: id + 1,
            slot: id + 1,
            block_hash: [u8::try_from(id).unwrap() + 10; 32],
            history_root,
            ..start
        });
    }
    (boundaries, contexts)
}

fn boundary(count: usize) -> ConsensusBoundary {
    chain().0[count]
}

/// A light client trusting boundary 1 at time 110, expiring at 210.
fn client() -> LightClient {
    LightClient::new(
        &spec(),
        Checkpoint {
            chain: chain_binding(),
            boundary: boundary(1),
        },
        110,
        2,
    )
    .unwrap()
}

fn proof(end: usize) -> HistoryProof {
    let (boundaries, _) = chain();
    HistoryProof {
        statement: ChunkReceiptStatement {
            statement: ConsensusStatement {
                chain: chain_binding(),
                start: boundaries[end - 1],
                end: boundaries[end],
                chunk: ChunkProofPublicInputs {
                    chunk_id: boundaries[end - 1].next_chunk_id,
                    start_height: boundaries[end].height,
                    end_height: boundaries[end].height,
                    start_state_root: [2; 32],
                    end_state_root: [2; 32],
                    start_block_hash: boundaries[end - 1].block_hash,
                    end_block_hash: boundaries[end].block_hash,
                    block_hash_root: [0; 32],
                    block_proof_root: [0; 32],
                    vrf_proof_root: [0; 32],
                    active_validator_set_root: boundaries[end].validators_root,
                    next_validator_set_root: boundaries[end].validators_root,
                    next_identity_sanctions_root: [0; 32],
                    da_root: [0; 32],
                },
                finality_cert_hash: [0; 32],
            },
            chunk_prover_address: [0; 32],
        },
        receipt: BoundedBytes::new(alloc::vec![1]).unwrap(),
    }
}

fn target(proof: &HistoryProof) -> Hash {
    proof.end_checkpoint().hash()
}

#[test]
fn advancement_is_authenticated_and_replay_does_not_refresh_expiry() {
    let mut client = client();
    let receipt = proof(2);
    let before = client.clone();
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 2)),
            target(&receipt),
            120,
            &Verifier(false)
        ),
        Err(LightClientError::Verification)
    );
    assert_eq!(client, before);
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 2)),
            target(&receipt),
            120,
            &Verifier(true)
        ),
        Ok(UpdateOutcome::Advanced)
    );
    let after = client.clone();
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 2)),
            target(&receipt),
            130,
            &Verifier(true)
        ),
        Ok(UpdateOutcome::AlreadyCurrent)
    );
    assert_eq!(client, after);
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 2)),
            target(&receipt),
            220,
            &Verifier(true)
        ),
        Err(LightClientError::Expired)
    );
}

#[test]
fn even_an_accepted_receipt_cannot_change_the_pinned_fact_identity() {
    let mut client = client();
    let before = client.clone();
    let mut receipt = proof(2);
    receipt.statement.statement.end.programs.execution.fact = [9; 8];
    assert_eq!(
        client.accept(&receipt, None, target(&receipt), 120, &Verifier(true),),
        Err(LightClientError::Range),
    );
    assert_eq!(client, before);
    receipt.statement.statement.chain.chain_spec_hash = [9; 32];
    assert_eq!(
        client.accept(&receipt, None, target(&receipt), 120, &Verifier(true),),
        Err(LightClientError::Domain),
    );
    assert_eq!(client, before);
}

#[test]
fn trust_moves_only_forward_and_conflicts_at_its_own_count() {
    let mut client = client();
    let before = client.clone();
    let mut conflict = proof(1);
    conflict.statement.statement.end.block_hash = [99; 32];
    assert_eq!(
        client.accept(&conflict, None, target(&conflict), 110, &Verifier(true)),
        Err(LightClientError::Conflict)
    );
    assert_eq!(client, before);
    // A later receipt is accepted only with an opening placing the current
    // anchor on its chain; without one, nothing shows it contains the anchor.
    let receipt = proof(3);
    assert_eq!(
        client.accept(&receipt, None, target(&receipt), 130, &Verifier(true)),
        Err(LightClientError::MissingOpening)
    );
    assert_eq!(client, before);
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 3)),
            target(&receipt),
            130,
            &Verifier(true)
        ),
        Ok(UpdateOutcome::Advanced)
    );
    assert_eq!(client.checkpoint(), &receipt.end_checkpoint());
    // An older endpoint never replaces a newer one.
    let after = client.clone();
    let older = proof(2);
    assert_eq!(
        client.accept(&older, None, target(&older), 130, &Verifier(true)),
        Err(LightClientError::Backwards)
    );
    assert_eq!(client, after);
}

/// Opening of leaf `index` under the history root of the chain's boundary
/// `count`.
fn opening(index: usize, count: usize) -> AnchorOpening {
    let (_, contexts) = chain();
    let leaves: Vec<_> = contexts[..count].iter().map(commitment).collect();
    AnchorOpening {
        context: contexts[index],
        path: neutrin0_consensus_types::history::HistoryPath::build(&leaves, index).unwrap(),
    }
}

#[test]
fn a_supplied_opening_proves_or_refutes_that_the_new_chain_extends_the_anchor() {
    // The client trusts boundary 1; the provider opens leaf 1 under
    // boundary 3, whose chain therefore contains the anchor.
    let receipt = proof(3);
    let mut extended = client();
    assert_eq!(
        extended.accept(
            &receipt,
            Some(&opening(1, 3)),
            target(&receipt),
            130,
            &Verifier(true)
        ),
        Ok(UpdateOutcome::Advanced)
    );
    // A path that does not verify is the provider's fault.
    let mut broken = opening(1, 3);
    broken.path.siblings[0][0] ^= 1;
    let mut client = client();
    let before = client.clone();
    assert_eq!(
        client.accept(
            &receipt,
            Some(&broken),
            target(&receipt),
            130,
            &Verifier(true)
        ),
        Err(LightClientError::BadOpening)
    );
    // A verified opening whose leaf started from another boundary shows the
    // new chain does not contain the trusted anchor.
    let mut forked = Checkpoint {
        chain: chain_binding(),
        boundary: boundary(1),
    };
    forked.boundary.state_root = [8; 32];
    let mut forked = LightClient::new(&spec(), forked, 110, 2).unwrap();
    assert_eq!(
        forked.accept(
            &receipt,
            Some(&opening(1, 3)),
            target(&receipt),
            130,
            &Verifier(true)
        ),
        Err(LightClientError::AnchorConflict)
    );
    assert_eq!(client, before);
}

fn advert(chunks: u64, byte: u8) -> sampling::Advertisement {
    sampling::Advertisement {
        chunks,
        checkpoint_hash: [byte; 32],
    }
}

#[test]
fn a_quorum_of_identical_advertisements_selects_the_highest_endpoint() {
    use sampling::{Decision, decide};
    let current = advert(2, 2);
    // Three of five agree on 4; the single peer at 5 is not enough.
    let samples = [
        advert(4, 4),
        advert(4, 4),
        advert(5, 5),
        advert(4, 4),
        advert(3, 3),
    ];
    assert_eq!(
        decide(current, &samples, 3),
        Decision::Advance(advert(4, 4))
    );
    // With a quorum of one, the highest advertisement wins.
    assert_eq!(
        decide(current, &samples, 1),
        Decision::Advance(advert(5, 5))
    );
    // Peers that are behind or level never move trust.
    assert_eq!(
        decide(current, &[advert(2, 2), advert(1, 1), advert(2, 2)], 1),
        Decision::Wait
    );
}

#[test]
fn insufficient_agreement_waits() {
    use sampling::{Decision, decide};
    let current = advert(2, 2);
    let samples = [advert(4, 4), advert(4, 4), advert(5, 5), advert(3, 3)];
    assert_eq!(decide(current, &samples, 3), Decision::Wait);
    assert_eq!(decide(current, &[], 1), Decision::Wait);
}

#[test]
fn different_endpoints_at_one_count_are_a_conflict_once_two_peers_back_each() {
    use sampling::{Decision, decide};
    let current = advert(2, 2);
    // Two peers each back a different endpoint at count 4.
    let samples = [advert(4, 4), advert(4, 4), advert(4, 9), advert(4, 9)];
    assert_eq!(
        decide(current, &samples, 2),
        Decision::Conflict {
            chunks: 4,
            first: [4; 32],
            second: [9; 32],
        }
    );
    // Two peers contradicting the current endpoint at its own count.
    assert_eq!(
        decide(current, &[advert(5, 5), advert(2, 7), advert(2, 7)], 1),
        Decision::Conflict {
            chunks: 2,
            first: [2; 32],
            second: [7; 32],
        }
    );
    // The backed conflict at the highest count is reported.
    assert_eq!(
        decide(
            current,
            &[
                advert(1, 1),
                advert(1, 8),
                advert(1, 8),
                advert(6, 6),
                advert(6, 9),
                advert(6, 9),
                advert(6, 6)
            ],
            1
        ),
        Decision::Conflict {
            chunks: 6,
            first: [6; 32],
            second: [9; 32],
        }
    );
    // Genesis is trusted locally and never sampled.
    assert_eq!(
        decide(advert(0, 0), &[advert(0, 7), advert(1, 1)], 1),
        Decision::Advance(advert(1, 1))
    );
}

#[test]
fn a_lone_contradicting_peer_is_checked_without_holding_the_client_back() {
    use sampling::{Decision, Disagreement, decide, disagreements};
    let current = advert(2, 2);
    // One peer disagrees with a quorum at count 4: the client advances.
    let samples = [advert(4, 4), advert(4, 4), advert(4, 9), advert(4, 4)];
    assert_eq!(
        decide(current, &samples, 3),
        Decision::Advance(advert(4, 4))
    );
    // One peer contradicts the current endpoint: nothing waits on it.
    assert_eq!(
        decide(current, &[advert(5, 5), advert(2, 7)], 1),
        Decision::Advance(advert(5, 5))
    );
    // Both disagreements are still reported, unbacked, to check alongside.
    assert_eq!(
        disagreements(current, &samples),
        vec![Disagreement {
            chunks: 4,
            first: [4; 32],
            second: [9; 32],
            backed: false,
        }]
    );
    assert_eq!(
        disagreements(current, &[advert(5, 5), advert(2, 7)]),
        vec![Disagreement {
            chunks: 2,
            first: [2; 32],
            second: [7; 32],
            backed: false,
        }]
    );
}

#[test]
fn sampling_policy_bounds() {
    use sampling::{MAX_SAMPLE_PEERS, SamplingPolicy};
    assert!(SamplingPolicy::DEFAULT.is_valid());
    assert_eq!(
        SamplingPolicy::default(),
        SamplingPolicy {
            peers: 5,
            quorum: 3
        }
    );
    for invalid in [
        SamplingPolicy {
            peers: 3,
            quorum: 0,
        },
        SamplingPolicy {
            peers: 3,
            quorum: 4,
        },
        SamplingPolicy {
            peers: MAX_SAMPLE_PEERS + 1,
            quorum: 1,
        },
    ] {
        assert!(!invalid.is_valid());
    }
}

#[test]
fn domain_target_clock_and_expiry_fail_without_mutation() {
    let mut client = client();
    let before = client.clone();
    let receipt = proof(2);
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 2)),
            target(&receipt),
            110,
            &Verifier(true)
        ),
        Err(LightClientError::Future)
    );
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 2)),
            target(&receipt),
            160,
            &Verifier(true)
        ),
        Err(LightClientError::Stale)
    );
    assert_eq!(
        client.accept(
            &receipt,
            Some(&opening(1, 2)),
            [99; 32],
            120,
            &Verifier(true)
        ),
        Err(LightClientError::UnexpectedTarget)
    );
    let mut wrong = receipt;
    wrong.statement.statement.chain.chain_spec_hash[0] ^= 1;
    assert_eq!(
        client.accept(&wrong, None, target(&wrong), 120, &Verifier(true)),
        Err(LightClientError::Domain)
    );
    assert_eq!(client, before);
}

#[test]
fn persistent_snapshot_does_not_renew_trust_on_restart() {
    let spec = spec();
    let original = client();
    let bytes = borsh::to_vec(&original.snapshot()).unwrap();
    let saved: LightClientSnapshot = borsh::from_slice(&bytes).unwrap();
    let mut restored = LightClient::restore(&spec, &original.trusted_domain(), &saved, 2).unwrap();
    assert_eq!(restored, original);
    let receipt = proof(2);
    assert_eq!(
        restored.accept(
            &receipt,
            None,
            target(&receipt),
            saved.anchor_expires_at,
            &Verifier(true)
        ),
        Err(LightClientError::Expired)
    );
    let mut wrong = saved;
    wrong.checkpoint.chain.chain_spec_hash[0] ^= 1;
    assert_eq!(
        LightClient::restore(&spec, &original.trusted_domain(), &wrong, 2),
        Err(LightClientError::Domain)
    );
}

/// Trusting an old boundary late does not restart its weak-subjectivity
/// period: boundary 1 was produced at 110, so trust taken at 500 expires at 210,
/// not 600.
#[test]
fn late_trust_in_an_old_boundary_keeps_its_age() {
    let anchor = Checkpoint {
        chain: chain_binding(),
        boundary: boundary(1),
    };
    let client = LightClient::new(&spec(), anchor, 500, 2).unwrap();
    assert_eq!(client.snapshot().anchor_expires_at, 210);
}

#[test]
fn genesis_trust_checks_all_boundary_lanes() {
    let spec = spec();
    let mut anchor = Checkpoint {
        chain: chain_binding(),
        boundary: ConsensusBoundary::genesis(&spec),
    };
    let mut client = LightClient::new(&spec, anchor, spec.genesis_time, 2).unwrap();
    let receipt = proof(2);
    assert_eq!(
        client.accept(&receipt, None, target(&receipt), 120, &Verifier(true)),
        Ok(UpdateOutcome::Advanced)
    );
    anchor.boundary.history_root = [99; 32];
    assert_eq!(
        LightClient::new(&spec, anchor, spec.genesis_time, 2),
        Err(LightClientError::InvalidAnchor)
    );
}
