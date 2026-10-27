//! Real-signature phase/leader/pacemaker simulations, independent of proving cost.

use super::*;
use crate::EngineError;
use crate::bft_loop::BftAction;
use crate::bft_loop::tests::{chain_spec_with, dummy_chunk, proposer, test_engine};
use crate::signing::SigningViolation;
use alloc::collections::VecDeque;
use neutrin0_consensus_types::{
    FinalityVote, FinalityVoteData, FinalityVotePhase, NilVoteData, RoundChange, bft_leader,
};
use neutrin0_storage::MemoryDatabase;

extern crate alloc;

#[test]
fn candidate_cache_keeps_every_live_quorum_dependency_within_its_bound() {
    let spec = chain_spec_with(1);
    let mut engine = test_engine(spec.clone());
    let mut candidates: Vec<_> = (0..64_u8)
        .map(|byte| {
            let mut candidate = dummy_chunk(0, spec.genesis_validator_set_root);
            candidate.end_state_root = [byte; 32];
            candidate
        })
        .collect();
    candidates.sort_by_key(Chunk::hash);
    // Bookkeeping isolation: these five dependencies are populated directly.
    // Production admission separately proves each branch and authenticates QCs.
    let pinned = candidates[..5].to_vec();
    let replacement = candidates[5].clone();
    engine.open_bft_session_at(pinned[0].clone(), 10).unwrap();
    let mut session = engine.bft_sessions.get(&0).unwrap().clone();
    let key = proposer(0);
    let quorum = |chunk: &Chunk| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            selection: PaymentSelection::default().commitment(),
            phase: FinalityVotePhase::Prevote,
        };
        QuorumCertificate {
            aggregate: neutrin0_consensus_types::AggregatedVote {
                aggregation_bits: neutrin0_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
                signature: key.sign_finality_vote(spec.consensus_domain(), &data),
            },
            data,
        }
    };
    let report = |chunk: &Chunk, round| {
        let mut report = RoundChange {
            chunk_id: 0,
            round,
            validator_index: 0,
            highest_quorum: Some(quorum(chunk)),
            signature: [0; 96],
        };
        report.signature = key
            .sign_raw(&report.signing_message(spec.consensus_domain()))
            .to_bytes();
        report
    };
    session.valid_value = Some((
        pinned[1].clone(),
        PaymentSelection::default(),
        quorum(&pinned[1]),
    ));
    session.highest_lock = Some(quorum(&pinned[2]));
    session.round_certificate = Some(RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports: vec![report(&pinned[3], 1)],
    });
    session.local_round_report = Some(report(&pinned[4], 2));
    for candidate in candidates.into_iter().skip(1) {
        Engine::<MemoryDatabase>::remember_bft_candidate(&mut session, candidate);
        assert!(session.candidates.len() <= 8);
    }
    assert_eq!(session.candidates.len(), 8);
    for candidate in &pinned {
        assert_eq!(
            session.candidate_by_hash(&candidate.hash()),
            Some(candidate)
        );
    }
    // A newly highest value must be pinned before eviction. Its small hash
    // would otherwise make it the first unprotected victim of a full cache.
    let mut higher_quorum = quorum(&replacement);
    higher_quorum.data.round = 1;
    higher_quorum.aggregate.signature =
        key.sign_finality_vote(spec.consensus_domain(), &higher_quorum.data);
    assert!(Engine::<MemoryDatabase>::remember_bft_valid_value(
        &mut session,
        replacement.clone(),
        PaymentSelection::default(),
        higher_quorum.clone(),
    ));
    // An equal-ranked repetition is not a new valid value.
    assert!(!Engine::<MemoryDatabase>::remember_bft_valid_value(
        &mut session,
        replacement.clone(),
        PaymentSelection::default(),
        higher_quorum,
    ));
    assert_eq!(session.candidates.len(), 8);
    assert_eq!(
        session.candidate_by_hash(&replacement.hash()),
        Some(&replacement)
    );
}

fn deliver_proposal(
    engine: &mut Engine<MemoryDatabase>,
    proposal: BftProposal,
    now: u64,
) -> Vec<BftAction> {
    // These fixtures deliberately isolate BFT from full branch proof validation.
    // Production enters through observe_bft_proposal's independently validated witness.
    engine.verify_bft_proposal_hint(&proposal).unwrap();
    let id = proposal.chunk.chunk_id;
    let mut session = engine.bft_sessions.get(&id).unwrap().clone();
    if proposal.round != session.round() {
        return Vec::new();
    }
    let actions = engine
        .accept_bft_leader_proposal(&mut session, proposal, now)
        .unwrap();
    engine.persist_bft_session(&session).unwrap();
    engine.bft_sessions.insert(id, session);
    actions
}

fn deliver(
    nodes: &mut [Engine<MemoryDatabase>],
    initial: Vec<BftAction>,
    now: u64,
    drop_precommits: bool,
) {
    let mut queue = VecDeque::from(initial);
    let mut budget = 10_000;
    while let Some(action) = queue.pop_front() {
        budget -= 1;
        assert!(
            budget > 0,
            "BFT effect graph must terminate without a polling loop"
        );
        for node in nodes.iter_mut() {
            let next = match &action {
                BftAction::BroadcastProposal(proposal) => {
                    deliver_proposal(node, *proposal.clone(), now)
                }
                BftAction::BroadcastPrevote(vote) => {
                    node.observe_finality_vote_at(vote.clone(), now).unwrap()
                }
                BftAction::BroadcastPrecommit(vote) if !drop_precommits => {
                    node.observe_finality_vote_at(vote.clone(), now).unwrap()
                }
                BftAction::BroadcastNilVote(vote) => {
                    node.observe_nil_vote(vote.clone(), now).unwrap()
                }
                BftAction::BroadcastRoundChange(report) => {
                    node.observe_round_change(report.clone(), now).unwrap()
                }
                BftAction::BroadcastRoundChangeCertificate(certificate) => node
                    .observe_round_change_certificate(certificate.clone(), now)
                    .unwrap(),
                _ => Vec::new(),
            };
            queue.extend(next);
        }
    }
}

fn check_certificates(nodes: &[Engine<MemoryDatabase>], minimum_round: u32) {
    for node in nodes {
        let session = node.bft_session(0).unwrap();
        assert!(session.precommit_quorum_observed());
        assert!(session.round() >= minimum_round);
        let cert = session
            .chunk_bft()
            .try_finalize(node.chain_spec().genesis_validator_set_root)
            .unwrap()
            .unwrap();
        neutrin0_prover_chunk::finality::verify_finality(
            node.chain_spec().consensus_domain(),
            &node.chain_spec().consensus,
            node.active_validator_set(),
            &node.finalized_seed(),
            &session.chunk,
            &cert,
        )
        .unwrap();
    }
}

#[test]
fn missing_first_leader_converges_with_one_quarter_unresponsive_stake() {
    let mut spec = chain_spec_with(4);
    spec.consensus.bft_round_timeout_base_secs = 1;
    spec.consensus.bft_round_timeout_step_secs = 1;
    let missing = bft_leader(
        spec.chain_id,
        0,
        0,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let mut nodes: Vec<_> = (0..4)
        .filter(|index| u32::from(*index) != missing)
        .map(|index| {
            let mut engine = test_engine(spec.clone());
            engine.set_local_voter(proposer(index));
            assert!(
                engine
                    .open_bft_session_at(chunk.clone(), 0)
                    .unwrap()
                    .is_empty()
            );
            engine
        })
        .collect();
    for now in 1..=8 {
        let actions = nodes
            .iter_mut()
            .flat_map(|node| node.tick_bft_round_timeouts(now).unwrap())
            .collect();
        deliver(&mut nodes, actions, now, false);
        if nodes
            .iter()
            .all(|node| node.bft_session(0).unwrap().precommit_quorum_observed())
        {
            break;
        }
    }
    check_certificates(&nodes, 1);
}

#[test]
fn lost_precommit_phase_preserves_lock_and_reproposes_highest_valid_value() {
    let mut spec = chain_spec_with(4);
    spec.consensus.bft_round_timeout_base_secs = 1;
    spec.consensus.bft_round_timeout_step_secs = 1;
    let leader = bft_leader(
        spec.chain_id,
        0,
        0,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    let missing = (leader + 3) % 4;
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let mut initial = Vec::new();
    let mut nodes: Vec<_> = (0..4)
        .filter(|index| u32::from(*index) != missing)
        .map(|index| {
            let mut engine = test_engine(spec.clone());
            engine.set_local_voter(proposer(index));
            initial.extend(engine.open_bft_session_at(chunk.clone(), 0).unwrap());
            engine
        })
        .collect();
    deliver(&mut nodes, initial, 0, true);
    for node in &nodes {
        let session = node.bft_session(0).unwrap();
        assert!(session.local_precommitted());
        assert_eq!(
            session.highest_lock_quorum().unwrap().data.chunk_hash,
            chunk.hash()
        );
    }
    for now in 1..=10 {
        let actions = nodes
            .iter_mut()
            .flat_map(|node| node.tick_bft_round_timeouts(now).unwrap())
            .collect();
        deliver(&mut nodes, actions, now, false);
        if nodes
            .iter()
            .all(|node| node.bft_session(0).unwrap().precommit_quorum_observed())
        {
            break;
        }
    }
    check_certificates(&nodes, 1);
    for node in &nodes {
        let proposal = node.bft_session(0).unwrap().proposal().unwrap();
        assert_eq!(proposal.chunk.hash(), chunk.hash());
        let valid = proposal.valid_quorum.as_ref().unwrap();
        assert_eq!(valid.data.round, 0);
        // The re-proposal carries exactly the selection its quorum signed.
        assert_eq!(valid.data.selection, proposal.selection());
    }
}

#[test]
fn nil_and_value_share_one_durable_phase_reservation() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    let voter = proposer(0);
    let nil = engine
        .sign_nil_vote_durable(
            &voter,
            NilVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Prevote,
            },
        )
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(
        restarted
            .sign_nil_vote_durable(&voter, nil.data.clone())
            .unwrap(),
        nil
    );
    assert!(matches!(
        restarted.sign_vote_durable(
            &voter,
            FinalityVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Prevote,
                chunk_hash: [3; 32],
                selection: crate::bft_loop::fixture_selection(),
            },
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    let value: FinalityVote = restarted
        .sign_vote_durable(
            &voter,
            FinalityVoteData {
                chunk_id: 0,
                round: 1,
                phase: FinalityVotePhase::Prevote,
                chunk_hash: [3; 32],
                selection: crate::bft_loop::fixture_selection(),
            },
            Vec::new(),
            None,
        )
        .unwrap();
    assert!(matches!(
        restarted.sign_nil_vote_durable(
            &voter,
            NilVoteData {
                chunk_id: value.data.chunk_id,
                round: value.data.round,
                phase: value.data.phase,
            }
        ),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
}

#[test]
fn alternative_valid_leader_report_subset_survives_restart() {
    let spec = chain_spec_with(4);
    let first_leader = bft_leader(
        spec.chain_id,
        0,
        0,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    let next_leader = bft_leader(
        spec.chain_id,
        0,
        1,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    let follower = (0..4)
        .find(|index| *index != first_leader && *index != next_leader)
        .unwrap();
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(u8::try_from(follower).unwrap()));
    engine.open_bft_session_at(chunk.clone(), 100).unwrap();
    let reports: Vec<_> = (0..4)
        .map(|index| {
            let mut report = RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: index,
                highest_quorum: None,
                signature: [0; 96],
            };
            report.signature = proposer(u8::try_from(index).unwrap())
                .sign_raw(&report.signing_message(spec.consensus_domain()))
                .to_bytes();
            report
        })
        .collect();
    engine
        .observe_round_change_certificate(
            RoundChangeCertificate {
                chunk_id: 0,
                round: 1,
                reports: reports.clone(),
            },
            110,
        )
        .unwrap();
    let leader_certificate = RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports: reports[..3].to_vec(),
    };
    let (proposal_slot, receipts, ratified_chunk_proofs) =
        engine.proposal_selection(&chunk).unwrap();
    let mut proposal = BftProposal {
        chunk,
        round: 1,
        proposer_index: next_leader,
        valid_quorum: None,
        round_change_certificate: Some(leader_certificate.clone()),
        proposal_slot,
        receipts,
        ratified_chunk_proofs,
        signature: [0; 96],
    };
    proposal.signature = proposer(u8::try_from(next_leader).unwrap())
        .sign_raw(&proposal.signing_message(spec.consensus_domain()))
        .to_bytes();
    deliver_proposal(&mut engine, proposal.clone(), 111);
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(proposer(u8::try_from(follower).unwrap()));
    assert_eq!(
        restarted.bft_session(0).unwrap().round_change_certificate(),
        Some(&leader_certificate)
    );
    assert_eq!(
        restarted.bft_session(0).unwrap().proposal(),
        Some(&proposal)
    );
    assert!(
        restarted.resume_bft_actions().unwrap().iter().any(
            |action| matches!(action, BftAction::BroadcastPrevote(vote) if vote.data.round == 1)
        )
    );
}

#[test]
fn observed_value_quorum_receives_a_fresh_precommit_deadline() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine
        .open_authorized_bft_session_at(chunk.clone(), 0)
        .unwrap();
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        chunk_hash: chunk.hash(),
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let voter = proposer(1);
    let vote = FinalityVote {
        proof_manifests: Vec::new(),
        data: data.clone(),
        aggregation_bits: neutrin0_primitives::BitVec::from_bytes(3, vec![2]).unwrap(),
        signature: voter.sign_finality_vote(spec.consensus_domain(), &data),
        attestations: vec![voter.attest_vote(spec.consensus_domain(), data, Vec::new(), None)],
    };
    let base = spec.consensus.bft_round_timeout_base_secs;
    let actions = engine.observe_finality_vote_at(vote, base - 1).unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, BftAction::BroadcastPrecommit(_)))
    );
    assert!(engine.tick_bft_round_timeouts(base).unwrap().is_empty());
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    let actions = engine.tick_bft_round_timeouts(2 * base - 1).unwrap();
    assert!(actions.iter().any(
        |action| matches!(action, BftAction::BroadcastRoundChange(report)
        if report.round == 1 && report.highest_quorum.is_some())
    ));
}

#[test]
fn nil_precommit_quorum_closes_old_phases_before_restart_or_late_messages() {
    // Any three of four seats are strictly more than two thirds.
    let spec = chain_spec_with(4);
    let mut engine = test_engine(spec.clone());
    engine
        .open_authorized_bft_session_at(dummy_chunk(0, spec.genesis_validator_set_root), 0)
        .unwrap();
    let mut signers = test_engine(spec.clone());
    for index in [1, 2, 3] {
        let vote = signers
            .sign_nil_vote_durable(
                &proposer(index),
                NilVoteData {
                    chunk_id: 0,
                    round: 0,
                    phase: FinalityVotePhase::Precommit,
                },
            )
            .unwrap();
        engine.observe_nil_vote(vote, 1).unwrap();
    }
    let session = engine.bft_session(0).unwrap();
    assert_eq!(
        session.pacemaker.step(),
        neutrin0_consensus_chunk_bft::RoundStep::AwaitRound
    );
    let deadline = session.pacemaker.deadline();
    let proposal = session.proposal().unwrap().clone();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(proposer(0));
    assert!(
        !restarted
            .resume_bft_actions()
            .unwrap()
            .iter()
            .any(|action| matches!(
                action,
                BftAction::BroadcastPrevote(_)
                    | BftAction::BroadcastPrecommit(_)
                    | BftAction::BroadcastNilVote(_)
            ))
    );
    assert!(deliver_proposal(&mut restarted, proposal, 2).is_empty());
    for index in [1, 2, 3] {
        let vote = signers
            .sign_nil_vote_durable(
                &proposer(index),
                NilVoteData {
                    chunk_id: 0,
                    round: 0,
                    phase: FinalityVotePhase::Prevote,
                },
            )
            .unwrap();
        let actions = restarted.observe_nil_vote(vote, 2).unwrap();
        assert!(!actions.iter().any(|action| matches!(
            action,
            BftAction::BroadcastPrevote(_)
                | BftAction::BroadcastPrecommit(_)
                | BftAction::BroadcastNilVote(_)
        )));
    }
    assert_eq!(
        restarted.bft_session(0).unwrap().pacemaker.deadline(),
        deadline
    );
}

#[test]
fn nil_quorum_round_entry_feeds_the_new_leader_prevote_to_fork_choice() {
    // The three peers of a four-seat set are strictly more than two thirds.
    let spec = chain_spec_with(4);
    let leader = bft_leader(
        spec.chain_id,
        0,
        1,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    let peers: Vec<_> = (0..4_u32).filter(|index| *index != leader).collect();
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(u8::try_from(leader).unwrap()));
    engine
        .open_bft_session_at(dummy_chunk(0, spec.genesis_validator_set_root), 0)
        .unwrap();
    // Two peer reports plus the leader's own make three of four seats.
    for peer in &peers[..2] {
        let mut report = RoundChange {
            chunk_id: 0,
            round: 1,
            validator_index: *peer,
            highest_quorum: None,
            signature: [0; 96],
        };
        report.signature = proposer(u8::try_from(*peer).unwrap())
            .sign_raw(&report.signing_message(spec.consensus_domain()))
            .to_bytes();
        assert!(engine.observe_round_change(report, 1).unwrap().is_empty());
    }
    let mut signers = test_engine(spec);
    let mut actions = Vec::new();
    for index in peers {
        let vote = signers
            .sign_nil_vote_durable(
                &proposer(u8::try_from(index).unwrap()),
                NilVoteData {
                    chunk_id: 0,
                    round: 0,
                    phase: FinalityVotePhase::Precommit,
                },
            )
            .unwrap();
        actions.extend(engine.observe_nil_vote(vote, 2).unwrap());
    }
    // The nil precommit quorum completes the round-one certificate, so this
    // entry point itself signs the new leader's proposal and value prevote.
    assert_eq!(engine.bft_session(0).unwrap().round(), 1);
    let prevote = actions
        .iter()
        .find_map(|action| match action {
            BftAction::BroadcastPrevote(vote) => Some(vote.data.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(prevote.round, 1);
    let recorded = engine.fork_choice().vote_for_validator(leader).unwrap();
    assert_eq!(recorded.data, prevote);
}

/// An honest validator that moved its lock from A to B through a valid
/// precommit, and is then asked to prevote B again by a leader that carries no
/// QC, must declare B's locking QC as its unlock. Paired with its older
/// precommit for A, a prevote signed with `unlock_quorum: None` would be
/// admissible `LockViolation` evidence although every step followed the
/// protocol; the live slashing monitor synthesises exactly that pair.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Drives three complete rounds of one validator and checks the resulting evidence."
)]
fn honest_lock_target_prevote_declares_its_lock_quorum() {
    use crate::slashing::SlashingMonitor;
    use neutrin0_consensus_types::{LockEvidence, SlashingEvidence};
    use neutrin0_primitives::BitVec;
    use neutrin0_prover_chunk::slashing::{EvidenceError, verify_lock_violation};

    let mut spec = chain_spec_with(4);
    spec.consensus.bft_round_timeout_base_secs = 1;
    spec.consensus.bft_round_timeout_step_secs = 1;
    let domain = spec.consensus_domain();
    let validators = spec.initial_validators.clone();
    let leader =
        |round: u32| bft_leader(spec.chain_id, 0, round, &spec.genesis_seed, &validators).unwrap();
    // Four equal validators rotate leadership; the victim never leads here.
    let victim = leader(3);
    assert!((0..3).all(|round| leader(round) != victim));
    let others: Vec<u8> = (0..4_u8).filter(|i| u32::from(*i) != victim).collect();

    let signed_proposal =
        |chunk: Chunk, round: u32, certificate: Option<RoundChangeCertificate>| {
            let mut proposal = BftProposal {
                chunk,
                round,
                proposer_index: leader(round),
                valid_quorum: None,
                round_change_certificate: certificate,
                proposal_slot: 0,
                receipts: Vec::new(),
                ratified_chunk_proofs: Vec::new(),
                signature: [0; 96],
            };
            proposal.signature = proposer(u8::try_from(leader(round)).unwrap())
                .sign_raw(&proposal.signing_message(domain))
                .to_bytes();
            proposal
        };
    let prevote_from = |index: u8, chunk_hash: neutrin0_primitives::Hash, round: u32| {
        let key = proposer(index);
        let data = FinalityVoteData {
            chunk_id: 0,
            round,
            chunk_hash,
            selection: crate::bft_loop::fixture_selection(),
            phase: FinalityVotePhase::Prevote,
        };
        let mut bits = BitVec::default();
        for position in 0..4_u8 {
            bits.push(position == index);
        }
        let claim = key.attest_vote(domain, data.clone(), Vec::new(), None);
        FinalityVote {
            aggregation_bits: bits,
            signature: claim.vote_signature,
            data,
            attestations: vec![claim],
            proof_manifests: Vec::new(),
        }
    };
    // The other three validators certify round entry without any known QC:
    // they never observed the polkas the victim acted on.
    let certificate_from = |round: u32| RoundChangeCertificate {
        chunk_id: 0,
        round,
        reports: others
            .iter()
            .map(|index| {
                let mut report = RoundChange {
                    chunk_id: 0,
                    round,
                    validator_index: u32::from(*index),
                    highest_quorum: None,
                    signature: [0; 96],
                };
                report.signature = proposer(*index)
                    .sign_raw(&report.signing_message(domain))
                    .to_bytes();
                report
            })
            .collect(),
    };
    let precommit_of = |actions: &[BftAction]| {
        actions.iter().find_map(|action| match action {
            BftAction::BroadcastPrecommit(vote) => Some(vote.clone()),
            _ => None,
        })
    };
    let prevote_of = |actions: &[BftAction]| {
        actions.iter().find_map(|action| match action {
            BftAction::BroadcastPrevote(vote) => Some(vote.clone()),
            _ => None,
        })
    };

    let chunk_a = dummy_chunk(0, spec.genesis_validator_set_root);
    let mut chunk_b = chunk_a.clone();
    chunk_b.end_state_root = [0x55; 32];
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(u8::try_from(victim).unwrap()));
    let mut now = 0;
    assert!(
        engine
            .open_bft_session_at(chunk_a.clone(), now)
            .unwrap()
            .is_empty()
    );

    // Round 0: the leader proposes A, the victim prevotes it, a polka for A
    // arrives and the victim precommits A, locking on A@0.
    let actions = deliver_proposal(&mut engine, signed_proposal(chunk_a.clone(), 0, None), now);
    assert!(prevote_of(&actions).is_some());
    let mut first_precommit = None;
    for index in &others[..2] {
        let actions = engine
            .observe_finality_vote_at(prevote_from(*index, chunk_a.hash(), 0), now)
            .unwrap();
        first_precommit = first_precommit.or_else(|| precommit_of(&actions));
    }
    let first_precommit = first_precommit.expect("victim precommits A after the round-0 polka");
    let lock_a0 = engine
        .bft_session(0)
        .unwrap()
        .highest_lock_quorum()
        .unwrap()
        .clone();
    assert_eq!(lock_a0.data.chunk_hash, chunk_a.hash());

    // The precommit phase times out; the other three certify round 1.
    let mut reported = false;
    while !reported {
        now += 1;
        reported = engine
            .tick_bft_round_timeouts(now)
            .unwrap()
            .iter()
            .any(|action| matches!(action, BftAction::BroadcastRoundChange(_)));
        assert!(now < 20);
    }
    engine
        .observe_round_change_certificate(certificate_from(1), now)
        .unwrap();
    assert_eq!(engine.bft_session(0).unwrap().round(), 1);

    // Round 1: the leader proposes B with no QC. The victim is locked on A and
    // prevotes nil, then sees a polka for B@1 and legitimately precommits B
    // with that polka as its signed unlock. Its lock is now B@1.
    let actions = deliver_proposal(
        &mut engine,
        signed_proposal(chunk_b.clone(), 1, Some(certificate_from(1))),
        now,
    );
    assert!(prevote_of(&actions).is_none());
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, BftAction::BroadcastNilVote(_)))
    );
    let mut relock_precommit = None;
    for index in &others {
        let actions = engine
            .observe_finality_vote_at(prevote_from(*index, chunk_b.hash(), 1), now)
            .unwrap();
        relock_precommit = relock_precommit.or_else(|| precommit_of(&actions));
    }
    let relock_precommit = relock_precommit.expect("victim precommits B after the round-1 polka");
    let unlock_b1 = relock_precommit.attestations[0]
        .unlock_quorum
        .clone()
        .unwrap();
    assert_eq!(unlock_b1.data.round, 1);
    assert_eq!(
        engine
            .bft_session(0)
            .unwrap()
            .highest_lock_quorum()
            .unwrap()
            .data
            .chunk_hash,
        chunk_b.hash()
    );

    // Round 1 also fails; the other three certify round 2 without a QC.
    let mut reported = false;
    while !reported {
        now += 1;
        reported = engine
            .tick_bft_round_timeouts(now)
            .unwrap()
            .iter()
            .any(|action| matches!(action, BftAction::BroadcastRoundChange(_)));
        assert!(now < 40);
    }
    engine
        .observe_round_change_certificate(certificate_from(2), now)
        .unwrap();
    assert_eq!(engine.bft_session(0).unwrap().round(), 2);

    // Round 2: the leader proposes B again, carrying no QC. B is the victim's
    // lock target, so the driver prevotes it, declaring the QC that locked B.
    let actions = deliver_proposal(
        &mut engine,
        signed_proposal(chunk_b, 2, Some(certificate_from(2))),
        now,
    );
    let prevote_b2 = prevote_of(&actions).expect("victim prevotes its lock target");
    let claim_b2 = prevote_b2.attestations[0].clone();
    assert_eq!(claim_b2.unlock_quorum.as_ref(), Some(&unlock_b1));

    // Every message above was produced by the honest driver. Pairing the
    // round-0 precommit for A with the round-2 prevote for B must be excused
    // by the signed unlock in the shared guest verifier.
    let quorum = (
        spec.consensus.bft_prevote_quorum_numerator,
        spec.consensus.bft_prevote_quorum_denominator,
    );
    let vote_a = first_precommit.attestations[0].indexed_vote();
    let vote_b1 = relock_precommit.attestations[0].indexed_vote();
    let vote_b2 = claim_b2.indexed_vote();
    // The intermediate precommit is correctly excused by its signed unlock.
    assert_eq!(
        verify_lock_violation(
            domain,
            &validators,
            victim,
            (&vote_a, &vote_b1),
            &LockEvidence {
                locked_prevote_quorum: lock_a0.clone(),
                attestation: relock_precommit.attestations[0].clone(),
            },
            quorum,
        ),
        Err(EvidenceError::HonestUnlock)
    );
    let evidence = LockEvidence {
        locked_prevote_quorum: lock_a0.clone(),
        attestation: claim_b2.clone(),
    };
    assert_eq!(
        verify_lock_violation(
            domain,
            &validators,
            victim,
            (&vote_a, &vote_b2),
            &evidence,
            quorum,
        ),
        Err(EvidenceError::HonestUnlock)
    );
    // The live slashing monitor still pairs the votes; the engine's recheck
    // must reject the synthesised report before any reporter could submit it.
    let mut monitor = SlashingMonitor::new();
    monitor.record_prevote_quorum(lock_a0);
    monitor.record_prevote_quorum(unlock_b1);
    for claim in [
        first_precommit.attestations[0].clone(),
        relock_precommit.attestations[0].clone(),
        claim_b2,
    ] {
        monitor.record_attestation(claim);
    }
    assert!(monitor.record_indexed_vote(victim, &vote_a).is_none());
    let intermediate = monitor.record_indexed_vote(victim, &vote_b1);
    assert!(matches!(
        intermediate,
        Some(SlashingEvidence::LockViolation { .. })
    ));
    assert!(
        engine
            .verify_slashing_evidence(&intermediate.unwrap())
            .is_err()
    );
    // The monitor sees that the signer re-locked on B under an observed polka
    // between the two rounds and does not synthesise a report at all.
    assert!(monitor.record_indexed_vote(victim, &vote_b2).is_none());
}

#[test]
fn a_deferred_proposal_is_judged_at_its_first_arrival() {
    let spec = chain_spec_with(1);
    let mut engine = test_engine(spec.clone());
    let proposal = BftProposal {
        chunk: dummy_chunk(0, spec.genesis_validator_set_root),
        round: 0,
        proposer_index: 0,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    let now = engine.proposal_arrival(&proposal);
    // Had it first arrived earlier, every retry keeps that slot.
    let key = neutrin0_consensus_types::tagged_commitment(b"proposal-arrival", &proposal);
    engine
        .proposal_arrivals
        .insert(key, (0, 0, now.saturating_sub(5)));
    assert_eq!(engine.proposal_arrival(&proposal), now.saturating_sub(5));
    // A leader signing many proposals for its round records only a few.
    for slot in 1..10 {
        let mut other = proposal.clone();
        other.proposal_slot = slot;
        engine.proposal_arrival(&other);
    }
    assert_eq!(engine.proposal_arrivals.len(), 4);
    assert!(engine.proposal_arrivals.contains_key(&key));
    // The record is bounded overall, the oldest arrival forgotten first.
    for round in 1..100 {
        let mut other = proposal.clone();
        other.round = round;
        engine.proposal_arrival(&other);
    }
    assert_eq!(engine.proposal_arrivals.len(), 64);
    assert!(!engine.proposal_arrivals.contains_key(&key));
}
