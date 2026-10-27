use super::*;
use crate::Engine;
use crate::validator_set::validator_set_root;
use neutrin0_consensus_types::Chunk;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH,
};
use neutrin0_storage::Database;
use neutrin0_storage::MemoryDatabase;

pub(super) fn test_engine(spec: ChainSpec) -> Engine<MemoryDatabase> {
    test_engine_on(spec, MemoryDatabase::new())
}

pub(super) fn test_engine_on(spec: ChainSpec, db: MemoryDatabase) -> Engine<MemoryDatabase> {
    let mut engine = Engine::genesis(spec, db).unwrap();
    // Session tests exercise BFT separately from block execution.
    for height in 1..=12 {
        let header = neutrin0_consensus_types::Header {
            height,
            slot: height,
            parent_hash: engine.head_hash(),
            proposer_index: 0,
            vrf_proof: [0; 96],
            state_root: [0; 32],
            transactions_root: [0; 32],
            votes_root: [0; 32],
            da_root: [0; 32],
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            gas_limit: 0,
            timestamp: 0,
            signature: [0; 96],
        };
        let hash = engine.store_mut().put_header(&header).unwrap();
        engine
            .commit_materialized_head(height, hash, header.state_root, None)
            .unwrap();
        let public_inputs = neutrin0_consensus_types::BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 7,
            height,
            parent_block_hash: header.parent_hash,
            block_hash: hash,
            state_root_before: [0; 32],
            state_root_after: [0; 32],
            transactions_root: [0; 32],
            receipt_root: [0; 32],
            da_root: [0; 32],
            vm_code_hash: [0; 32],
            block_program: [0; 8],
            gas_used: 0,
            gas_limit: 0,
            proposer_address: [0; 32],
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
        };
        engine
            .store_mut()
            .put_block_proof(
                &hash,
                &neutrin0_consensus_types::BlockProof {
                    prover_address: public_inputs.proposer_address,
                    statement_key: [0; 32],
                    height,
                    block_hash: hash,
                    public_inputs,
                    proof_bytes: vec![1],
                },
            )
            .unwrap();
    }
    engine
}

fn test_vote(
    chunk_id: ChunkId,
    chunk_hash: ChunkHash,
    round: u32,
    phase: FinalityVotePhase,
    domain: ConsensusDomain,
    voter: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let mut vote = super::build_local_vote(
        chunk_id,
        chunk_hash,
        round,
        phase,
        domain,
        voter,
        active_set_len,
    );
    if phase == FinalityVotePhase::Precommit {
        vote.proof_manifests = vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![[1; 32]],
        }];
        vote.attestations = vec![voter.attest_vote(domain, vote.data.clone(), vec![[1; 32]], None)];
    }
    vote
}

#[test]
fn slashing_reuses_import_signature_verdicts_and_still_attributes_conflicts() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    let chunk_hash = dummy_chunk(0, spec.genesis_validator_set_root).hash();
    let vote = test_vote(
        0,
        chunk_hash,
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    assert!(engine.validate_signed_artifact(
        &neutrin0_consensus_types::signed_artifacts::SignedArtifact::Vote(vote.clone())
    ));
    let imported = engine.bls_verifier.borrow().checks;
    assert_eq!(
        engine.observe_votes_for_slashing(&vote).unwrap(),
        Vec::new()
    );
    assert_eq!(
        engine.bls_verifier.borrow().checks,
        imported,
        "import already verified every equation slashing needs"
    );
    // A conflicting vote is new: its signature is verified and the
    // equivocation is attributed.
    let mut other = chunk_hash;
    other[0] ^= 1;
    let conflicting = test_vote(
        0,
        other,
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    let evidence = engine.observe_votes_for_slashing(&conflicting).unwrap();
    assert!(engine.bls_verifier.borrow().checks > imported);
    assert_eq!(evidence.len(), 1);
    // A forged signature is still refused.
    let mut forged = test_vote(
        0,
        other,
        1,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    forged.signature = vote.signature;
    assert!(engine.observe_vote_for_slashing(&forged).is_err());
}

pub(super) fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

/// Every seat but the last weighs double, so for three seats the local
/// voter and its first peer (`{0, 1}`, 4/5) hold strictly more than two
/// thirds while no other pair does; larger sets keep every equal-weight
/// quorum shape.
fn validators_with_keys(n: u8) -> Vec<Validator> {
    (0..n)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account([0x33; 20]),
            effective_stake: if i + 1 == n {
                32_000_000_000_000_000_000
            } else {
                64_000_000_000_000_000_000
            },
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

pub(super) fn chain_spec_with(n: u8) -> ChainSpec {
    let validators = validators_with_keys(n);
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xAA; 32];

    // Keep the foundational session tests deterministic by
    // pinning `expected_aggregators_per_round` to a value so
    // small that no validator clears the VRF threshold. Tests
    // that want aggregator behaviour build their own spec via
    // [`chain_spec_with_aggregators`].
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_aggregators_per_round: 1,
        ..ConsensusParams::default()
    };
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"bft-loop-test".to_vec()).expect("name fits"),
        chain_id: 7,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xCC; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0xCC; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

fn chain_spec_with_aggregators(n: u8) -> ChainSpec {
    let mut spec = chain_spec_with(n);
    // Pin a large expectation so every validator clears the
    // aggregator threshold deterministically.
    spec.consensus.expected_aggregators_per_round =
        neutrin0_primitives::fixed_u128_from_integer(100);
    spec
}

pub(super) fn dummy_chunk(
    chunk_id: ChunkId,
    active_validator_set_root: neutrin0_primitives::Hash,
) -> Chunk {
    // Match the header fixture's timestamp and gas fields used above.
    let mut parent = [0xAA; 32];
    let mut start = parent;
    for height in 1..=chunk_id + 1 {
        start = parent;
        let mut header = crate::test_db::header(height, height, parent, ZERO_HASH);
        header.timestamp = 0;
        header.gas_limit = 0;
        parent = header.hash();
    }
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id,
        start_height: chunk_id.saturating_mul(1) + 1,
        end_height: chunk_id.saturating_mul(1) + 1,
        start_state_root: ZERO_HASH,
        end_state_root: [0x77; 32],
        start_block_hash: start,
        end_block_hash: parent,
        block_hash_root: [0xCC; 32],
        block_proof_root: [0xDD; 32],
        vrf_proof_root: [0xEE; 32],
        active_validator_set_root,
        next_validator_set_root: active_validator_set_root,
        da_root: [0x33; 32],
    }
}

/// Round-zero proposal signed by the designated leader of `chunk`.
fn round_zero_proposal<DB: Database>(engine: &Engine<DB>, chunk: Chunk) -> BftProposal {
    let index = neutrin0_consensus_types::bft_leader(
        engine.chain_spec().chain_id,
        chunk.chunk_id,
        0,
        &engine.finalized_seed(),
        engine.active_validator_set(),
    )
    .unwrap();
    // Each fixture uses these deterministic identities. Signing tests
    // pass their own proposal helper because their key material differs.
    // Fixture votes sign the fixed selection, which bypasses the
    // network's selection rules like the direct acceptance below.
    let mut proposal = BftProposal {
        chunk,
        round: 0,
        proposer_index: index,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    proposal.signature = proposer(u8::try_from(index).unwrap())
        .sign_raw(&proposal.signing_message(engine.consensus_domain()))
        .to_bytes();
    proposal
}

impl<DB: Database> Engine<DB> {
    /// Install an actual signed leader proposal in isolated BFT fixtures.
    /// Tests of the public proposal/branch boundary use the production API.
    pub(crate) fn open_authorized_bft_session_at(
        &mut self,
        chunk: Chunk,
        now: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        // A local stake-weighted leader would sign its own selection;
        // fixtures install the fixed one whoever leads.
        let mut actions = self.open_fixture_bft_session_at(chunk.clone(), now)?;
        if self
            .bft_session(chunk.chunk_id)
            .expect("opened fixture")
            .proposal
            .is_none()
        {
            let chunk_id = chunk.chunk_id;
            let proposal = round_zero_proposal(self, chunk);
            let mut session = self.bft_sessions.get(&chunk_id).unwrap().clone();
            actions.extend(self.accept_bft_leader_proposal(&mut session, proposal, now)?);
            self.persist_bft_session(&session)?;
            self.bft_sessions.insert(chunk_id, session);
            self.feed_broadcast_actions_to_fork_choice(&actions);
        }
        actions.retain(|action| !matches!(action, BftAction::BroadcastProposal(_)));
        Ok(actions)
    }

    pub(crate) fn accept_authorized_bft_fixture(
        &mut self,
        proposal: BftProposal,
        now: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = proposal.chunk.chunk_id;
        let mut session = self
            .bft_sessions
            .get(&id)
            .expect("opened fixture session")
            .clone();
        let actions = self.accept_bft_leader_proposal(&mut session, proposal, now)?;
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    pub(crate) fn open_authorized_bft_session(
        &mut self,
        chunk: Chunk,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.open_authorized_bft_session_at(chunk, 0)
    }
}

#[test]
fn single_validator_session_self_finalises_via_local_vote_quorum() {
    let spec = chain_spec_with(1);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let actions = engine
        .open_authorized_bft_session(chunk)
        .expect("open session");
    assert_eq!(actions.len(), 3);
    assert!(matches!(actions[0], BftAction::BroadcastPrevote(_)));
    assert!(matches!(actions[1], BftAction::BroadcastPrecommit(_)));
    assert!(matches!(actions[2], BftAction::QuorumReached(identity) if identity.chunk_id == 0));
    let session = engine.bft_session(0).expect("session present");
    assert!(session.local_prevoted());
    assert!(session.local_precommitted());
    assert!(session.prevote_quorum_observed());
    assert!(session.precommit_quorum_observed());
}

#[test]
fn three_validator_session_advances_on_peer_quorum() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let actions = engine
        .open_authorized_bft_session(chunk.clone())
        .expect("open session");
    assert_eq!(actions.len(), 1, "only the local prevote until peers vote");
    assert!(matches!(actions[0], BftAction::BroadcastPrevote(_)));
    let session = engine.bft_session(0).expect("session present");
    assert!(session.local_prevoted());
    assert!(!session.prevote_quorum_observed());

    // Feed v1's prevote — now we have 2/3 stake → emit precommit.
    let v1_prevote = test_vote(
        0,
        chunk.hash(),
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    let actions = engine
        .observe_finality_vote(v1_prevote)
        .expect("ingest v1 prevote");
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], BftAction::BroadcastPrecommit(_)));
    let session = engine.bft_session(0).expect("session present");
    assert!(session.prevote_quorum_observed());
    assert!(session.local_precommitted());
    assert!(!session.precommit_quorum_observed());

    // Feed v1's precommit — now 2/3 precommit stake → quorum reached.
    let v1_precommit = test_vote(
        0,
        chunk.hash(),
        0,
        FinalityVotePhase::Precommit,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    let actions = engine
        .observe_finality_vote(v1_precommit)
        .expect("ingest v1 precommit");
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], BftAction::QuorumReached(identity) if identity.chunk_id == 0));
    let session = engine.bft_session(0).expect("session present");
    assert!(session.precommit_quorum_observed());
}

#[test]
fn later_prevote_unions_preserve_the_exact_lock_without_promoting_extra_quorums() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine.open_authorized_bft_session(chunk.clone()).unwrap();
    for index in [1, 2] {
        engine
            .observe_finality_vote(test_vote(
                0,
                chunk.hash(),
                0,
                FinalityVotePhase::Prevote,
                spec.consensus_domain(),
                &proposer(index),
                3,
            ))
            .unwrap();
        assert!(engine.bft_session(0).unwrap().local_precommitted());
    }
    let session = engine.bft_session(0).unwrap();
    let locked = session.highest_lock_quorum().unwrap().clone();
    let expanded = QuorumCertificate {
        data: locked.data.clone(),
        aggregate: session
            .chunk_bft()
            .current_aggregate(FinalityVotePhase::Prevote)
            .unwrap(),
    };
    assert_ne!(
        expanded.aggregate.aggregation_bits,
        locked.aggregate.aggregation_bits
    );
    assert_eq!(session.highest_valid_quorum(), Some(&locked));
    let original_source =
        neutrin0_consensus_types::signed_artifacts::SignedArtifact::Quorum(locked);
    let extra_source = neutrin0_consensus_types::signed_artifacts::SignedArtifact::Quorum(expanded);
    assert!(
        engine
            .store()
            .signed_artifact(&original_source.id())
            .unwrap()
            .is_some()
    );
    assert!(
        engine
            .store()
            .signed_artifact(&extra_source.id())
            .unwrap()
            .is_none()
    );
}

#[test]
fn complete_certificate_identity_stays_fixed_after_later_signed_votes_and_restart() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine.open_authorized_bft_session(chunk.clone()).unwrap();
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let actions = engine
            .observe_finality_vote(test_vote(
                0,
                chunk.hash(),
                0,
                phase,
                spec.consensus_domain(),
                &proposer(1),
                3,
            ))
            .unwrap();
        if phase == FinalityVotePhase::Precommit {
            assert!(
                actions
                    .iter()
                    .any(|action| matches!(action, BftAction::QuorumReached(_)))
            );
        }
    }
    let original = engine.bft_session(0).unwrap().quorum_identity().unwrap();
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let later = test_vote(
            0,
            chunk.hash(),
            0,
            phase,
            spec.consensus_domain(),
            &proposer(2),
            3,
        );
        neutrin0_prover_chunk::finality::verify_vote_signatures(
            spec.consensus_domain(),
            &spec.initial_validators,
            &later,
            &spec.consensus,
        )
        .unwrap();
        let mut forged = later.clone();
        forged.signature = [0; 96];
        assert!(engine.observe_finality_vote(forged).is_err());
        assert!(engine.observe_finality_vote(later).unwrap().is_empty());
        assert_eq!(
            engine.bft_session(0).unwrap().quorum_identity(),
            Some(original)
        );
    }
    let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
    restored.set_local_voter(proposer(0));
    assert!(
        restored
            .resume_bft_actions()
            .unwrap()
            .iter()
            .any(|action| matches!(action,
        BftAction::QuorumReached(identity) if *identity == original))
    );
    assert_eq!(
        restored.bft_session(0).unwrap().quorum_identity(),
        Some(original)
    );
}

#[test]
fn observe_drops_votes_for_unknown_chunks() {
    let spec = chain_spec_with(2);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let orphan_vote = test_vote(
        99,
        [0xAB; 32],
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(0),
        2,
    );
    let actions = engine.observe_finality_vote(orphan_vote).expect("no error");
    assert!(actions.is_empty(), "orphan votes are silently dropped");
    assert!(engine.bft_session(99).is_none());
}

/// Every accepted finality vote feeds the
/// fork-choice DAG with one `ChunkVote` per signer. Single-
/// signer votes contribute exactly one entry; aggregate votes
/// contribute one entry per set bit. The recorded weight is
/// the validator's `effective_stake` (matching `vote_stake`).
#[test]
fn observe_finality_vote_feeds_fork_choice() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));

    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let _ = engine
        .open_authorized_bft_session(chunk.clone())
        .expect("open session");
    // Opening the session emits v0's prevote internally, which
    // also flows through `observe_finality_vote` semantics — so
    // v0's vote should already be in fork-choice.
    assert_eq!(
        engine.fork_choice_vote_count(),
        1,
        "session open must feed v0's local prevote into fork choice (got {})",
        engine.fork_choice_vote_count(),
    );

    // Feed v1's prevote — fork-choice gains a second entry.
    let v1_prevote = test_vote(
        0,
        chunk.hash(),
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    engine
        .observe_finality_vote(v1_prevote)
        .expect("ingest v1 prevote");
    assert_eq!(
        engine.fork_choice_vote_count(),
        2,
        "v1's prevote must record into fork choice (got {})",
        engine.fork_choice_vote_count(),
    );

    // v1's subsequent precommit REPLACES the v1 prevote entry
    // (one slot per validator in fork_choice.votes), not appends.
    let v1_precommit = test_vote(
        0,
        chunk.hash(),
        0,
        FinalityVotePhase::Precommit,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    engine
        .observe_finality_vote(v1_precommit)
        .expect("ingest v1 precommit");
    assert_eq!(
        engine.fork_choice_vote_count(),
        2,
        "v1's precommit replaces v1's prevote entry; count stays at 2 (got {})",
        engine.fork_choice_vote_count(),
    );

    // The stored entry for v1 must reflect the latest phase and
    // the canonical stake weight.
    let v1_vote = engine
        .fork_choice()
        .vote_for_validator(1)
        .expect("v1's vote present");
    assert_eq!(v1_vote.data.chunk_id, 0);
    assert_eq!(v1_vote.data.phase, FinalityVotePhase::Precommit);
    assert_eq!(
        v1_vote.weight, spec.initial_validators[1].effective_stake,
        "fork-choice weight must equal v1's effective_stake",
    );
}

#[test]
fn opening_the_same_chunk_twice_errors() {
    let spec = chain_spec_with(2);
    let mut engine = test_engine(spec.clone());
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine
        .open_authorized_bft_session(chunk.clone())
        .expect("first open");
    let err = engine
        .open_authorized_bft_session(chunk)
        .expect_err("second open errors");
    assert!(matches!(
        err,
        BftLoopError::SessionAlreadyOpen { chunk_id: 0 }
    ));
}

#[test]
fn aggregator_emits_publish_actions_when_local_aggregate_grows() {
    let spec = chain_spec_with_aggregators(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    assert!(
        engine.local_is_aggregator_for(0, 0),
        "spec must elect v0 into the aggregator committee"
    );

    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let actions = engine
        .open_authorized_bft_session(chunk.clone())
        .expect("open session");
    let aggregate_prevotes = actions
        .iter()
        .filter(|a| matches!(a, BftAction::PublishAggregatePrevote { .. }))
        .count();
    assert_eq!(
        aggregate_prevotes, 1,
        "open with local prevote crosses 0 → 1 stake → one aggregate publish"
    );

    // Feed v1's prevote — aggregate stake grows from 1 to 2, so
    // another aggregate publish should fire.
    let v1_prevote = test_vote(
        0,
        chunk.hash(),
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    let actions = engine
        .observe_finality_vote(v1_prevote)
        .expect("ingest v1 prevote");
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, BftAction::PublishAggregatePrevote { .. })),
        "aggregate prevote publish must fire when stake grows from 1 → 2"
    );
    // The same prevote re-ingested produces no new publish
    // (aggregate stake did not change).
    let v1_prevote_dupe = test_vote(
        0,
        chunk.hash(),
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    let actions = engine
        .observe_finality_vote(v1_prevote_dupe)
        .expect("ingest duplicate v1 prevote");
    assert!(
        actions
            .iter()
            .all(|a| !matches!(a, BftAction::PublishAggregatePrevote { .. })),
        "duplicate vote must not retrigger aggregator publish"
    );
}

#[test]
fn aggregator_publish_subnet_matches_engine_helper() {
    let spec = chain_spec_with_aggregators(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk_id: ChunkId = 0;
    let chunk = {
        let mut c = dummy_chunk(chunk_id, spec.genesis_validator_set_root);
        c.start_height = chunk_id + 1;
        c.end_height = chunk_id + 1;
        c
    };
    let expected_subnet = engine.subnet_for_chunk(chunk_id);
    let actions = engine
        .open_authorized_bft_session(chunk)
        .expect("open session");
    let publish_subnet = actions
        .iter()
        .find_map(|a| match a {
            BftAction::PublishAggregatePrevote { subnet, .. } => Some(*subnet),
            _ => None,
        })
        .expect("aggregator publish must be present");
    assert_eq!(publish_subnet, expected_subnet);
}

#[test]
fn non_aggregator_never_emits_publish_actions() {
    // chain_spec_with pins expected_aggregators_per_round to a
    // value so small that no validator clears the threshold.
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    assert!(
        !engine.local_is_aggregator_for(0, 0),
        "spec must not elect any aggregator"
    );
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let actions = engine
        .open_authorized_bft_session(chunk)
        .expect("open session");
    assert!(actions.iter().all(|a| !matches!(
        a,
        BftAction::PublishAggregatePrevote { .. } | BftAction::PublishAggregatePrecommit { .. }
    )));
}

#[test]
fn non_voter_session_only_accumulates_peer_votes() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    // No local_voter configured: this is a follower-only node.
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let actions = engine
        .open_authorized_bft_session(chunk.clone())
        .expect("open session");
    assert!(
        actions.is_empty(),
        "follower-only nodes emit no votes on session open"
    );

    // Feed prevotes from v0 and v1 (2/3 stake) and precommits from
    // v0 and v1; even without a local validator, the session must
    // surface a QuorumReached action so the follower can persist
    // the cert.
    for index in 0_u8..2 {
        let vote = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(index),
            3,
        );
        engine.observe_finality_vote(vote).expect("ingest prevote");
    }
    let mut quorum_seen = false;
    for index in 0_u8..2 {
        let vote = test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Precommit,
            spec.consensus_domain(),
            &proposer(index),
            3,
        );
        let actions = engine
            .observe_finality_vote(vote)
            .expect("ingest precommit");
        if actions
            .iter()
            .any(|a| matches!(a, BftAction::QuorumReached(identity) if identity.chunk_id == 0))
        {
            quorum_seen = true;
        }
    }
    assert!(
        quorum_seen,
        "follower must observe quorum once 2/3 precommit stake arrives"
    );
}

#[test]
fn phase_timeout_emits_nil_precommit_before_requesting_next_round() {
    let spec = chain_spec_with(2);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine.open_authorized_bft_session_at(chunk, 0).unwrap();
    let base = spec.consensus.bft_round_timeout_base_secs;
    assert!(engine.tick_bft_round_timeouts(base - 1).unwrap().is_empty());
    let actions = engine.tick_bft_round_timeouts(base).unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, BftAction::BroadcastNilVote(vote)
        if vote.data.phase == FinalityVotePhase::Precommit))
    );
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    let actions = engine.tick_bft_round_timeouts(2 * base).unwrap();
    assert!(actions.iter().any(
        |action| matches!(action, BftAction::BroadcastRoundChange(report)
        if report.round == 1)
    ));
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    assert!(engine.tick_bft_round_timeouts(2 * base).unwrap().is_empty());
}

/// When the BFT loop observes a peer vote that
/// pushes a session past 2/3 prevote stake, the just-crossed
/// lock prevote quorum must be fed into the slashing monitor.
/// A subsequent cross-round conflicting precommit from the
/// same validator then triggers `LockViolation` synthesis.
#[test]
fn observe_finality_vote_feeds_lock_quorum_into_slashing_monitor() {
    use neutrin0_consensus_types::SlashingEvidence;

    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));

    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let chunk_hash = chunk.hash();
    let _ = engine
        .open_authorized_bft_session(chunk)
        .expect("open session");
    // After open, session has v0's prevote. With 3 validators
    // and 2/3 quorum, v0 alone is 1/3 → no quorum yet → no
    // lock evidence in the monitor.

    // Feed v1's prevote — crosses 2/3 prevote stake. The BFT
    // loop hook should snapshot the just-formed quorum into the
    // slashing monitor's `observed_prevote_quorums` cache.
    let v1_prevote = test_vote(
        0,
        chunk_hash,
        0,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    engine
        .observe_finality_vote(v1_prevote)
        .expect("ingest v1 prevote");

    // The slashing monitor now has a lock quorum for
    // (chunk_id=0, round=0, chunk_hash). v1 sends a round-0
    // precommit consistent with the lock, then later a
    // round-1 precommit for a DIFFERENT hash → must surface
    // LockViolation.
    let v1_precommit_r0 = test_vote(
        0,
        chunk_hash,
        0,
        FinalityVotePhase::Precommit,
        spec.consensus_domain(),
        &proposer(1),
        3,
    );
    let evidence = engine
        .observe_vote_for_slashing(&v1_precommit_r0)
        .expect("v1 precommit r0 recorded");
    assert!(
        evidence.is_none(),
        "first precommit registers without slashing"
    );

    // Now the conflicting cross-round precommit. Different
    // chunk_hash but same chunk_id; the lock quorum is in the
    // cache; no unlock quorum exists at any intervening round.
    let mut conflicting_chunk_hash = chunk_hash;
    conflicting_chunk_hash[0] ^= 0xFF;
    let mut v1_precommit_r1 = neutrin0_consensus_types::FinalityVote {
        proof_manifests: vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![[1; 32]],
        }],
        attestations: Vec::new(),
        aggregation_bits: {
            let mut bits = neutrin0_primitives::BitVec::default();
            for index in 0..3 {
                bits.push(index == 1);
            }
            bits
        },
        data: neutrin0_consensus_types::FinalityVoteData {
            chunk_id: 0,
            round: 1,
            chunk_hash: conflicting_chunk_hash,
            selection: crate::bft_loop::fixture_selection(),
            phase: FinalityVotePhase::Precommit,
        },
        signature: proposer(1).sign_finality_vote(
            spec.consensus_domain(),
            &neutrin0_consensus_types::FinalityVoteData {
                chunk_id: 0,
                round: 1,
                chunk_hash: conflicting_chunk_hash,
                selection: crate::bft_loop::fixture_selection(),
                phase: FinalityVotePhase::Precommit,
            },
        ),
    };
    v1_precommit_r1.attestations.push(proposer(1).attest_vote(
        spec.consensus_domain(),
        v1_precommit_r1.data.clone(),
        vec![[1; 32]],
        None,
    ));
    let evidence = engine
        .observe_vote_for_slashing(&v1_precommit_r1)
        .expect("v1 cross-round precommit recorded")
        .expect("LockViolation must be synthesised");
    match evidence {
        SlashingEvidence::LockViolation {
            validator_index,
            vote_a,
            vote_b,
            lock_evidence,
        } => {
            assert_eq!(validator_index, 1);
            assert_eq!(vote_a.data.round, 0);
            assert_eq!(vote_a.data.chunk_hash, chunk_hash);
            assert_eq!(vote_b.data.round, 1);
            assert_eq!(vote_b.data.chunk_hash, conflicting_chunk_hash);
            assert_eq!(lock_evidence.locked_prevote_quorum.data.round, 0);
            assert_eq!(
                lock_evidence.locked_prevote_quorum.data.chunk_hash,
                chunk_hash,
            );
            assert!(lock_evidence.attestation.unlock_quorum.is_none());
        }
        other => panic!("expected LockViolation, got {other:?}"),
    }
}

/// A prevote quorum completed by the local prevote while accepting the
/// leader proposal is lock evidence, exactly like one completed by a peer.
/// Peer prevotes that precede the proposal are held for its selection
/// (design 08) and count only once it is accepted.
#[test]
fn prevote_quorum_completed_by_a_leader_proposal_feeds_the_slashing_monitor() {
    // Local plus two peers of four seats: the peers alone are not a
    // quorum, and the local prevote makes three, strictly above 2/3.
    let spec = chain_spec_with(4);
    let leader = neutrin0_consensus_types::bft_leader(
        spec.chain_id,
        0,
        0,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    let local = u8::try_from((leader + 1) % 4).unwrap();
    let peers = [(leader + 2) % 4, (leader + 3) % 4].map(|peer| u8::try_from(peer).unwrap());
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(local));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    assert!(
        engine
            .open_bft_session_at(chunk.clone(), 0)
            .unwrap()
            .is_empty()
    );
    // The peer prevotes arrive before the proposal and are not a quorum.
    for peer in peers {
        engine
            .observe_finality_vote(test_vote(
                0,
                chunk.hash(),
                0,
                FinalityVotePhase::Prevote,
                spec.consensus_domain(),
                &proposer(peer),
                4,
            ))
            .unwrap();
    }
    assert!(!engine.bft_session(0).unwrap().prevote_quorum_observed());
    let proposal = round_zero_proposal(&engine, chunk);
    engine.accept_authorized_bft_fixture(proposal, 0).unwrap();
    let session = engine.bft_session(0).unwrap();
    assert!(session.prevote_quorum_observed());
    let lock = session.highest_lock_quorum().unwrap();
    assert!(engine.slashing_monitor.prevote_quorum_is_observed(lock));
}

/// Peer value votes are held before the leader proposal, per selection,
/// and survive restart. Raw votes without a proposal cannot finish the
/// session or surface a certificate; the late proposal completes it
/// without redelivery.
#[test]
fn restart_without_a_leader_proposal_keeps_raw_peer_quorums_unfinished() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    assert!(
        engine
            .open_bft_session_at(chunk.clone(), 0)
            .unwrap()
            .is_empty()
    );
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        // `{0, 1}` holds 4/5 of this weighted set.
        for index in [0, 1] {
            let actions = engine
                .observe_finality_vote(test_vote(
                    0,
                    chunk.hash(),
                    0,
                    phase,
                    spec.consensus_domain(),
                    &proposer(index),
                    3,
                ))
                .unwrap();
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, BftAction::QuorumReached(_)))
            );
        }
    }
    let session = engine.bft_session(0).unwrap();
    assert!(session.proposal().is_none());
    assert!(!session.chunk_bft().precommit_quorum_reached());
    assert_eq!(session.chunk_bft().pending_votes().len(), 2);
    assert!(!session.precommit_quorum_observed());

    let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
    let session = restored.bft_session(0).unwrap();
    assert_eq!(session.chunk_bft().pending_votes().len(), 2);
    assert!(!session.precommit_quorum_observed());
    assert!(
        !restored
            .resume_bft_actions()
            .unwrap()
            .iter()
            .any(|action| matches!(action, BftAction::QuorumReached(_)))
    );
    // The late proposal completes the certificate under the same rule.
    let proposal = round_zero_proposal(&restored, chunk);
    let actions = restored.accept_authorized_bft_fixture(proposal, 1).unwrap();
    let session = restored.bft_session(0).unwrap();
    assert!(session.precommit_quorum_observed());
    let reached: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            BftAction::QuorumReached(quorum) => Some(*quorum),
            _ => None,
        })
        .collect();
    assert_eq!(reached, [session.quorum_identity().unwrap()]);
}

/// Crossing a prevote quorum retains its QC only through the ordered
/// valid-value rule, which never demotes a higher-ranked value.
#[test]
fn crossing_a_prevote_quorum_cannot_demote_a_higher_ranked_valid_value() {
    let spec = chain_spec_with(3);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine.open_authorized_bft_session(chunk.clone()).unwrap();
    // Bookkeeping isolation: an equal-round QC for a larger target hash
    // outranks the current target under `qc_rank`.
    let higher = (0..=u8::MAX)
        .map(|byte| Chunk {
            end_state_root: [byte; 32],
            ..chunk.clone()
        })
        .find(|candidate| candidate.hash() > chunk.hash())
        .unwrap();
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        chunk_hash: higher.hash(),
        selection: PaymentSelection::default().commitment(),
        phase: FinalityVotePhase::Prevote,
    };
    let signatures: Vec<_> = [1, 2]
        .into_iter()
        .map(|index| {
            let voter = proposer(index);
            neutrin0_crypto::bls::Signature::from_bytes(
                &voter.sign_finality_vote(spec.consensus_domain(), &data),
            )
            .unwrap()
        })
        .collect();
    let higher_quorum = QuorumCertificate {
        data,
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: BitVec::from_bytes(3, vec![0b110]).unwrap(),
            signature: neutrin0_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        },
    };
    let mut session = engine.bft_sessions.get(&0).unwrap().clone();
    assert!(Engine::<MemoryDatabase>::remember_bft_valid_value(
        &mut session,
        higher,
        PaymentSelection::default(),
        higher_quorum.clone(),
    ));
    engine.bft_sessions.insert(0, session);

    engine
        .observe_finality_vote(test_vote(
            0,
            chunk.hash(),
            0,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            3,
        ))
        .unwrap();
    let session = engine.bft_session(0).unwrap();
    assert_eq!(
        session.highest_lock_quorum().unwrap().data.chunk_hash,
        chunk.hash()
    );
    assert_eq!(session.highest_valid_quorum(), Some(&higher_quorum));
}

#[test]
fn isolated_validator_retransmits_exact_round_report_without_forgetting_lock() {
    let spec = chain_spec_with(2);
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine.open_bft_session_at(chunk, 0).unwrap();
    let base = spec.consensus.bft_round_timeout_base_secs;
    let mut report = None;
    for now in [base, 2 * base, 3 * base, 4 * base] {
        for action in engine.tick_bft_round_timeouts(now).unwrap() {
            if let BftAction::BroadcastRoundChange(value) = action {
                if let Some(prior) = &report {
                    assert_eq!(prior, &value);
                }
                report = Some(value);
            }
        }
    }
    assert!(report.is_some());
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
}

fn aggregate_attested(
    spec: &ChainSpec,
    chunk: &Chunk,
    phase: FinalityVotePhase,
    round: u32,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        selection: crate::bft_loop::fixture_selection(),
        phase,
        round,
    };
    let mut attestations = Vec::new();
    let signatures: Vec<_> = (0..2)
        .map(|index| {
            let voter = proposer(index);
            attestations.push(voter.attest_vote(
                spec.consensus_domain(),
                data.clone(),
                if phase == FinalityVotePhase::Precommit {
                    vec![[1; 32]]
                } else {
                    Vec::new()
                },
                None,
            ));
            neutrin0_crypto::bls::Signature::from_bytes(
                &voter.sign_finality_vote(spec.consensus_domain(), &data),
            )
            .unwrap()
        })
        .collect();
    FinalityVote {
        proof_manifests: if phase == FinalityVotePhase::Precommit {
            vec![neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![[1; 32]],
            }]
        } else {
            Vec::new()
        },
        data,
        attestations,
        aggregation_bits: BitVec::from_bytes(2, vec![3]).unwrap(),
        signature: neutrin0_crypto::bls::aggregate_signatures(
            &signatures.iter().collect::<Vec<_>>(),
        )
        .unwrap()
        .to_bytes(),
    }
}

fn accountable_certificate(
    spec: &ChainSpec,
    chunk: &Chunk,
    round: u32,
) -> neutrin0_consensus_types::FinalityCert {
    let prevote = aggregate_attested(spec, chunk, FinalityVotePhase::Prevote, round);
    let precommit = aggregate_attested(spec, chunk, FinalityVotePhase::Precommit, round);
    let leader = neutrin0_consensus_types::bft_leader(
        7,
        chunk.chunk_id,
        round,
        &spec.genesis_seed,
        &validators_with_keys(2),
    )
    .unwrap();
    let round_change_certificate = (round > 0).then(|| {
        let reports = (0..2)
            .map(|index| {
                let mut report = RoundChange {
                    chunk_id: chunk.chunk_id,
                    round,
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
        RoundChangeCertificate {
            chunk_id: chunk.chunk_id,
            round,
            reports,
        }
    });
    let mut proposal = neutrin0_consensus_types::BftProposal {
        chunk: chunk.clone(),
        round,
        proposer_index: leader,
        valid_quorum: None,
        round_change_certificate,
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    proposal.signature = proposer(u8::try_from(leader).unwrap())
        .sign_raw(&proposal.signing_message(spec.consensus_domain()))
        .to_bytes();
    neutrin0_consensus_types::FinalityCert {
        proposal,
        chunk_id: chunk.chunk_id,
        round,
        chunk_hash: chunk.hash(),
        active_validator_set_root: chunk.active_validator_set_root,
        prevote: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: prevote.aggregation_bits,
            signature: prevote.signature,
        },
        precommit: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: precommit.aggregation_bits,
            signature: precommit.signature,
        },
        prevote_attestations: prevote.attestations,
        proof_manifests: precommit.proof_manifests,
        precommit_attestations: precommit.attestations,
    }
}

#[test]
fn certificates_alone_attribute_every_lock_violator() {
    let mut spec = chain_spec_with(2);
    spec.consensus.chunk_size = 1;
    let mut engine = test_engine(spec.clone());
    let first = dummy_chunk(0, spec.genesis_validator_set_root);
    let prior = accountable_certificate(&spec, &first, 0);
    assert_eq!(
        engine
            .observe_certificate_for_slashing(&first, &prior)
            .unwrap(),
        [] as [neutrin0_consensus_types::SlashingEvidence; 0]
    );
    let mut later = first;
    later.end_state_root[0] ^= 1;
    let certificate = accountable_certificate(&spec, &later, 2);
    let evidence = engine
        .observe_certificate_for_slashing(&later, &certificate)
        .unwrap();
    assert_eq!(
        evidence.len(),
        4,
        "both phases carry individual declarations"
    );
    for item in &evidence {
        assert!(matches!(
            item,
            neutrin0_consensus_types::SlashingEvidence::LockViolation { .. }
        ));
        engine.verify_slashing_evidence(item).unwrap();
    }
    // A valid signed unlock excuses both signers even though None did not.
    let quorum = neutrin0_consensus_types::QuorumCertificate {
        data: FinalityVoteData {
            phase: FinalityVotePhase::Prevote,
            ..certificate.precommit_vote().data
        },
        aggregate: certificate.prevote.clone(),
    };
    let earlier = aggregate_attested(&spec, &later, FinalityVotePhase::Prevote, 1);
    let prevote_unlock = QuorumCertificate {
        data: earlier.data,
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: earlier.aggregation_bits,
            signature: earlier.signature,
        },
    };
    let mut honest = certificate;
    for claim in &mut honest.prevote_attestations {
        *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
            spec.consensus_domain(),
            claim.vote.clone(),
            Vec::new(),
            Some(prevote_unlock.clone()),
        );
    }
    let manifests =
        neutrin0_consensus_types::ProofManifestIndex::new(&honest.proof_manifests).unwrap();
    for claim in &mut honest.precommit_attestations {
        *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
            spec.consensus_domain(),
            claim.vote.clone(),
            manifests
                .get(&claim.proof_acceptance.unwrap())
                .unwrap()
                .proof_hashes
                .clone(),
            Some(quorum.clone()),
        );
    }
    let mut engine = test_engine(spec.clone());
    engine
        .observe_certificate_for_slashing(&dummy_chunk(0, spec.genesis_validator_set_root), &prior)
        .unwrap();
    assert_eq!(
        engine
            .observe_certificate_for_slashing(&later, &honest)
            .unwrap(),
        [] as [neutrin0_consensus_types::SlashingEvidence; 0]
    );
    let mut stripped = honest;
    stripped.precommit_attestations[0].unlock_quorum = None;
    assert!(
        engine
            .observe_certificate_for_slashing(&later, &stripped)
            .is_err()
    );
}
#[test]
fn aggregate_votes_alone_preserve_lock_evidence() {
    let mut spec = chain_spec_with(2);
    spec.consensus.chunk_size = 1;
    let mut engine = test_engine(spec.clone());
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    let prevote = aggregate_attested(&spec, &chunk, FinalityVotePhase::Prevote, 0);
    let quorum = neutrin0_consensus_types::QuorumCertificate {
        data: prevote.data,
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: prevote.aggregation_bits,
            signature: prevote.signature,
        },
    };
    let mut first = aggregate_attested(&spec, &chunk, FinalityVotePhase::Precommit, 0);
    let manifests =
        neutrin0_consensus_types::ProofManifestIndex::new(&first.proof_manifests).unwrap();
    for claim in &mut first.attestations {
        *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
            spec.consensus_domain(),
            claim.vote.clone(),
            manifests
                .get(&claim.proof_acceptance.unwrap())
                .unwrap()
                .proof_hashes
                .clone(),
            Some(quorum.clone()),
        );
    }
    assert_eq!(
        engine.observe_votes_for_slashing(&first).unwrap(),
        [] as [neutrin0_consensus_types::SlashingEvidence; 0]
    );
    let mut later = chunk;
    later.end_state_root[0] ^= 1;
    let vote = aggregate_attested(&spec, &later, FinalityVotePhase::Precommit, 1);
    let evidence = engine.observe_votes_for_slashing(&vote).unwrap();
    assert_eq!(evidence.len(), 2);
    for item in evidence {
        engine.verify_slashing_evidence(&item).unwrap();
    }
}

#[test]
fn aggregate_illegal_prevotes_remain_attributable_when_the_signed_unlock_is_invalid() {
    let mut spec = chain_spec_with(2);
    spec.consensus.chunk_size = 1;
    let mut engine = test_engine(spec.clone());
    let first = dummy_chunk(0, spec.genesis_validator_set_root);
    engine
        .observe_certificate_for_slashing(&first, &accountable_certificate(&spec, &first, 0))
        .unwrap();
    let mut later = first;
    later.end_state_root[0] ^= 1;
    let mut vote = aggregate_attested(&spec, &later, FinalityVotePhase::Prevote, 2);
    let circular = QuorumCertificate {
        data: vote.data.clone(),
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: vote.aggregation_bits.clone(),
            signature: vote.signature,
        },
    };
    for claim in &mut vote.attestations {
        *claim = proposer(u8::try_from(claim.validator_index).unwrap()).attest_vote(
            spec.consensus_domain(),
            vote.data.clone(),
            Vec::new(),
            Some(circular.clone()),
        );
    }
    assert!(
        neutrin0_prover_chunk::finality::verify_vote(
            spec.consensus_domain(),
            &spec.initial_validators,
            &vote,
            &spec.consensus,
        )
        .is_err()
    );
    let evidence = engine.observe_votes_for_slashing(&vote).unwrap();
    assert_eq!(evidence.len(), 2);
    for item in evidence {
        let neutrin0_consensus_types::SlashingEvidence::LockViolation { vote_b, .. } = &item else {
            panic!("the signed circular unlock must establish a lock violation");
        };
        assert_eq!(vote_b.data.phase, FinalityVotePhase::Prevote);
        engine.verify_slashing_evidence(&item).unwrap();
    }
}

#[test]
fn signed_future_votes_cannot_erase_retained_accountability() {
    let mut spec = chain_spec_with(2);
    spec.consensus.chunk_size = 1;
    let mut engine = test_engine(spec.clone());
    let first = dummy_chunk(0, spec.genesis_validator_set_root);
    engine
        .observe_certificate_for_slashing(&first, &accountable_certificate(&spec, &first, 0))
        .unwrap();
    let mut later = first.clone();
    later.end_state_root[0] ^= 1;
    let later_vote = aggregate_attested(&spec, &later, FinalityVotePhase::Prevote, 2);
    assert_eq!(
        engine
            .observe_votes_for_slashing(&later_vote)
            .unwrap()
            .len(),
        2
    );
    let retained = engine.slashing_monitor.votes_tracked();

    let mut future = first;
    future.chunk_id = u64::MAX;
    let future_vote = aggregate_attested(&spec, &future, FinalityVotePhase::Prevote, 1);
    neutrin0_prover_chunk::finality::verify_vote_signatures(
        spec.consensus_domain(),
        &spec.initial_validators,
        &future_vote,
        &spec.consensus,
    )
    .expect("the attack has authentic vote and declaration signatures");
    let outside = crate::slashing::SlashingError::SourceOutsideAccountabilityWindow;
    assert_eq!(
        engine.observe_votes_for_slashing(&future_vote),
        Err(outside.clone())
    );
    assert_eq!(
        engine
            .observe_certificate_for_slashing(&future, &accountable_certificate(&spec, &future, 1)),
        Err(outside.clone())
    );
    let individual = test_vote(
        u64::MAX,
        future.hash(),
        1,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(0),
        2,
    );
    assert_eq!(
        engine.observe_vote_for_slashing(&individual),
        Err(outside.clone())
    );
    assert_eq!(
        engine.observe_vote_for_invalid_proof_signing(&future_vote),
        Err(outside)
    );
    assert_eq!(engine.slashing_monitor.votes_tracked(), retained);

    // No fresh claim is supplied: the prior lock, its QC, and the cached
    // later declaration must all survive the authentic future payload.
    let mut retry = test_vote(
        0,
        later.hash(),
        2,
        FinalityVotePhase::Prevote,
        spec.consensus_domain(),
        &proposer(0),
        2,
    );
    retry.attestations.clear();
    let offence = engine.observe_vote_for_slashing(&retry).unwrap().unwrap();
    assert!(matches!(
        offence,
        neutrin0_consensus_types::SlashingEvidence::LockViolation { .. }
    ));
    engine.verify_slashing_evidence(&offence).unwrap();
}

#[test]
fn signed_extreme_slots_cannot_erase_double_proposal_observations() {
    let spec = chain_spec_with(2);
    let mut engine = test_engine(spec.clone());
    let signer = proposer(0);
    let mut first = crate::test_db::header(1, 7, spec.genesis_block_hash, ZERO_HASH);
    first.signature = signer.sign_proposer_message(spec.consensus_domain(), &first.hash());
    assert!(
        engine
            .observe_header_for_slashing(&first)
            .unwrap()
            .is_none()
    );
    let mut extreme = first.clone();
    extreme.slot = u64::MAX;
    extreme.signature = signer.sign_proposer_message(spec.consensus_domain(), &extreme.hash());
    assert!(
        engine
            .observe_header_for_slashing(&extreme)
            .unwrap()
            .is_none()
    );
    assert_eq!(engine.slashing_monitor.headers_tracked(), 2);

    let mut future = extreme;
    future.height = u64::MAX;
    future.signature = signer.sign_proposer_message(spec.consensus_domain(), &future.hash());
    assert_eq!(
        engine.observe_header_for_slashing(&future),
        Err(crate::slashing::SlashingError::SourceOutsideAccountabilityWindow)
    );
    assert_eq!(engine.slashing_monitor.headers_tracked(), 2);
    let mut conflicting = first;
    conflicting.state_root[0] ^= 1;
    conflicting.signature =
        signer.sign_proposer_message(spec.consensus_domain(), &conflicting.hash());
    let offence = engine
        .observe_header_for_slashing(&conflicting)
        .unwrap()
        .unwrap();
    assert!(matches!(
        offence,
        neutrin0_consensus_types::SlashingEvidence::DoubleProposal { .. }
    ));
    engine.verify_slashing_evidence(&offence).unwrap();
}

#[test]
fn inactive_source_proposers_cannot_enter_header_attribution() {
    {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        let mut validators = spec.initial_validators.clone();
        validators[0].effective_stake = 0;
        engine
            .set_active_validator_set(1, validators.clone())
            .unwrap();
        let signer = proposer(0);
        let mut first = crate::test_db::header(1, 7, spec.genesis_block_hash, ZERO_HASH);
        first.signature = signer.sign_proposer_message(spec.consensus_domain(), &first.hash());
        crate::signature::verify_header_signature(&first, &validators, spec.consensus_domain())
            .expect("the inactive source has an authentic BLS signature");
        assert_eq!(
            neutrin0_prover_chunk::proposer::verify_header_signature(
                &first,
                spec.consensus_domain(),
                &validators,
            ),
            Err(neutrin0_prover_chunk::proposer::ProposerError::Validator)
        );
        let inactive = crate::slashing::SlashingError::EvidenceFieldsInconsistent;
        assert_eq!(
            engine.observe_header_for_slashing(&first),
            Err(inactive.clone())
        );
        let mut second = first.clone();
        second.state_root[0] ^= 1;
        second.signature = signer.sign_proposer_message(spec.consensus_domain(), &second.hash());
        assert_eq!(
            engine.verify_slashing_evidence(
                &neutrin0_consensus_types::SlashingEvidence::DoubleProposal {
                    proposer_index: 0,
                    header_a: first.clone(),
                    header_b: second,
                }
            ),
            Err(inactive)
        );
        assert_eq!(engine.slashing_monitor.headers_tracked(), 0);
    }
}

#[test]
fn inactive_source_single_signers_cannot_bypass_attribution_guards() {
    {
        let spec = chain_spec_with(2);
        let mut engine = test_engine(spec.clone());
        let partial = test_vote(
            0,
            [0x99; 32],
            1,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            2,
        );
        let indexed = partial.attestations[0].indexed_vote();
        crate::slashing::verify_indexed_vote_signature(
            1,
            &indexed,
            &spec.initial_validators,
            spec.consensus_domain(),
        )
        .expect("the inactive signer test uses an authentic individual signature");
        let mut validators = spec.initial_validators.clone();
        validators[1].effective_stake = 0;
        engine
            .set_active_validator_set(1, validators.clone())
            .unwrap();
        let inactive = crate::slashing::SlashingError::EvidenceFieldsInconsistent;
        assert_eq!(
            crate::slashing::verify_indexed_vote_signature(
                1,
                &indexed,
                &validators,
                spec.consensus_domain()
            ),
            Err(inactive.clone())
        );
        assert_eq!(
            crate::slashing::verify_vote_attestation(
                &partial.attestations[0],
                1,
                &partial.data,
                &validators,
                spec.consensus_domain()
            ),
            Err(inactive.clone())
        );
        assert!(
            neutrin0_prover_chunk::finality::verify_vote_signatures(
                spec.consensus_domain(),
                &validators,
                &partial,
                &spec.consensus,
            )
            .is_err()
        );
        assert_eq!(
            engine.observe_votes_for_slashing(&partial),
            Err(inactive.clone())
        );
        let conflicting = test_vote(
            0,
            [0x88; 32],
            1,
            FinalityVotePhase::Prevote,
            spec.consensus_domain(),
            &proposer(1),
            2,
        );
        assert_eq!(
            engine.verify_slashing_evidence(
                &neutrin0_consensus_types::SlashingEvidence::DoublePrevote {
                    validator_index: 1,
                    vote_a: indexed,
                    vote_b: conflicting.attestations[0].indexed_vote(),
                }
            ),
            Err(inactive)
        );
        assert_eq!(engine.slashing_monitor.votes_tracked(), 0);
    }
}
