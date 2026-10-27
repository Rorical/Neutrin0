//! Restart and storage-failure regressions for local anti-equivocation.

use super::*;
use crate::test_db::FaultDb;
use crate::{Engine, LocalSigningPolicy, ProductionConfig, ProposerKey, SignRequest};
use neutrin0_consensus_types::{Chunk, FinalityVote, NilVote, NilVoteAttestation, ProofManifest};
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH,
};
use neutrin0_storage::{Database, MemoryDatabase};

fn key(index: u32) -> ProposerKey {
    ProposerKey::from_ikm(&[u8::try_from(index + 1).unwrap(); 32], index).unwrap()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One pause/restart/resume scenario covers every signature kind and retained lock."
)]
fn operator_pause_survives_restart_and_preserves_reservations_and_lock() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    let vote_data = data(0, [1; 32], FinalityVotePhase::Precommit);
    let locked = quorum_for(&spec, vote_data.clone());
    let vote = engine
        .sign_vote_durable(
            &key(0),
            vote_data.clone(),
            vec![[3; 32]],
            Some(locked.clone()),
        )
        .unwrap();
    let policy = LocalSigningPolicy {
        signing_paused: true,
        production_paused: false,
    };
    engine.set_local_signing_policy(policy).unwrap();
    let journal = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
    restored.set_local_voter(key(0));
    assert_eq!(restored.local_signing_policy(), policy);
    assert!(restored.local_voter().is_some());
    assert!(restored.active_local_voter().is_none());
    assert_eq!(reserved_lock(&restored), Some(locked.clone()));
    assert!(matches!(
        restored.sign_vote_durable(
            &key(0),
            vote_data.clone(),
            vec![[3; 32]],
            Some(locked.clone())
        ),
        Err(EngineError::Signing(SigningViolation::Paused))
    ));
    assert!(matches!(
        restored.sign_nil_vote_durable(
            &key(0),
            NilVoteData {
                chunk_id: 0,
                round: 1,
                phase: FinalityVotePhase::Prevote
            }
        ),
        Err(EngineError::Signing(SigningViolation::Paused))
    ));
    assert!(matches!(
        restored.sign_proposal_durable(&key(0), &header(10, 1)),
        Err(EngineError::Signing(SigningViolation::Paused))
    ));
    assert!(matches!(
        restored
            .sign_bft_proposal_durable(&key(0), proposal_with_carriers(restored.chain_spec(), 1)),
        Err(EngineError::Signing(SigningViolation::Paused))
    ));
    assert!(matches!(
        restored.sign_round_change_durable(
            &key(0),
            RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: 0,
                highest_quorum: Some(locked.clone()),
                signature: [0; 96]
            }
        ),
        Err(EngineError::Signing(SigningViolation::Paused))
    ));
    assert!(
        restored
            .try_produce_block(
                1,
                ProductionConfig { proposer: &key(0) },
                neutrin0_consensus_types::Body::default(),
                &neutrin0_proof_system::UnsupportedExecutor
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        restored
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        journal
    );
    restored
        .set_local_signing_policy(LocalSigningPolicy::default())
        .unwrap();
    assert_eq!(
        restored
            .sign_vote_durable(&key(0), vote_data, vec![[3; 32]], Some(locked))
            .unwrap(),
        vote
    );
    assert!(
        restored
            .sign_vote_durable(
                &key(0),
                data(0, [2; 32], FinalityVotePhase::Precommit),
                vec![[3; 32]],
                None
            )
            .is_err()
    );
}

#[test]
fn production_pause_keeps_voting_and_shutdown_cannot_be_resumed() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    engine
        .set_local_signing_policy(LocalSigningPolicy {
            signing_paused: false,
            production_paused: true,
        })
        .unwrap();
    assert!(engine.active_local_voter().is_some());
    assert!(
        engine
            .try_produce_block(
                1,
                ProductionConfig { proposer: &key(0) },
                neutrin0_consensus_types::Body::default(),
                &neutrin0_proof_system::UnsupportedExecutor
            )
            .unwrap()
            .is_none()
    );
    engine
        .sign_nil_vote_durable(
            &key(0),
            NilVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Prevote,
            },
        )
        .unwrap();
    engine.stop_local_signer();
    assert!(
        engine
            .set_local_signing_policy(LocalSigningPolicy::default())
            .is_err()
    );
    assert!(engine.active_local_voter().is_none());
    let restarted = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert!(!restarted.local_signer_stopping());
    assert!(restarted.local_signing_policy().production_paused);
}

#[test]
fn control_storage_failure_closes_gates_and_corruption_refuses_startup() {
    let mut engine = Engine::genesis(spec(), FaultDb::default()).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(0);
    assert!(
        engine
            .set_local_signing_policy(LocalSigningPolicy::default())
            .is_err()
    );
    assert!(engine.local_control_faulted());
    assert!(!engine.local_production_enabled());
    assert!(matches!(
        engine.sign_proposal_durable(&key(0), &header(1, 1)),
        Err(EngineError::Signing(SigningViolation::Paused))
    ));
    engine.store_mut().db_mut().fail_durable_after = None;
    engine
        .set_local_signing_policy(LocalSigningPolicy::default())
        .unwrap();
    assert!(!engine.local_control_faulted());
    let mut db = engine.store().db().clone();
    db.put(Column::Meta, b"local:signing-policy", &[2]).unwrap();
    assert!(Engine::open(spec(), db).is_err());
}

#[test]
fn paused_observer_accumulates_peer_quorum_without_signing() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(2));
    engine
        .set_local_signing_policy(LocalSigningPolicy {
            signing_paused: true,
            production_paused: false,
        })
        .unwrap();
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    let before = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    for index in [0, 1] {
        engine
            .observe_finality_vote(peer_prevote(&spec, &candidate, index))
            .unwrap();
    }
    assert!(engine.bft_session(0).unwrap().prevote_quorum_observed());
    assert!(!engine.bft_session(0).unwrap().local_precommitted());
    engine.tick_bft_round_timeouts(10_000).unwrap();
    assert_eq!(
        before,
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap()
    );
    engine
        .set_local_signing_policy(LocalSigningPolicy::default())
        .unwrap();
    engine.resume_bft_actions().unwrap();
    assert!(engine.active_local_voter().is_some());
}

/// Seats weigh 2:2:1, so the local voter and peer 1 (`{0, 1}`, 4/5) hold
/// strictly more than two thirds while no other pair does.
fn spec() -> ChainSpec {
    let validators: Vec<_> = (0..3)
        .map(|index| Validator {
            pubkey: *key(index).public_key_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account([9; 20]),
            effective_stake: if index == 2 {
                32_000_000_000_000_000_000
            } else {
                64_000_000_000_000_000_000
            },
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect();
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"durable-signing".to_vec()).unwrap(),
        chain_id: 7,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [8; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [7; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash: [6; 32],
        genesis_validator_set_root: crate::validator_set_root(&validators),
        consensus: ConsensusParams {
            chunk_size: 1,
            ..ConsensusParams::default()
        },
        proof: ProofParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

fn data(round: u32, hash: Hash, phase: FinalityVotePhase) -> FinalityVoteData {
    FinalityVoteData {
        chunk_id: 0,
        round,
        chunk_hash: hash,
        selection: crate::bft_loop::fixture_selection(),
        phase,
    }
}

fn quorum_for(spec: &ChainSpec, mut data: FinalityVoteData) -> QuorumCertificate {
    data.phase = FinalityVotePhase::Prevote;
    let signatures: Vec<_> = (0..spec.initial_validators.len())
        .map(|index| {
            key(u32::try_from(index).unwrap()).sign_finality_vote(spec.consensus_domain(), &data)
        })
        .map(|bytes| neutrin0_crypto::bls::Signature::from_bytes(&bytes).unwrap())
        .collect();
    QuorumCertificate {
        data,
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: BitVec::from_bytes(
                u32::try_from(signatures.len()).unwrap(),
                vec![(1 << signatures.len()) - 1],
            )
            .unwrap(),
            signature: neutrin0_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        },
    }
}

/// A real nonzero-round signed carrier with an earlier QC and all reports.
fn proposal_with_carriers(spec: &ChainSpec, round: u32) -> BftProposal {
    let candidate = chunk(spec);
    let quorum = quorum_for(spec, data(0, candidate.hash(), FinalityVotePhase::Prevote));
    let reports = (0..u32::try_from(spec.initial_validators.len()).unwrap())
        .map(|index| {
            let mut report = RoundChange {
                chunk_id: candidate.chunk_id,
                round,
                validator_index: index,
                highest_quorum: Some(quorum.clone()),
                signature: [0; 96],
            };
            report.signature = key(index)
                .sign_raw(&report.signing_message(spec.consensus_domain()))
                .to_bytes();
            report
        })
        .collect();
    let proposer_index = neutrin0_consensus_types::bft_leader(
        spec.chain_id,
        candidate.chunk_id,
        round,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    BftProposal {
        chunk: candidate,
        round,
        proposer_index,
        valid_quorum: Some(quorum),
        round_change_certificate: Some(neutrin0_consensus_types::RoundChangeCertificate {
            chunk_id: 0,
            round,
            reports,
        }),
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    }
}

/// Durable lock retained by `key(0)` for chunk zero.
fn reserved_lock<DB: Database>(engine: &Engine<DB>) -> Option<QuorumCertificate>
where
    DB::Error: fmt::Debug,
{
    engine
        .reserved_signing_progress(&key(0), 0)
        .unwrap()
        .and_then(|progress| progress.locked)
}

fn chunk(spec: &ChainSpec) -> Chunk {
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [4; 32],
        block_hash_root: [5; 32],
        block_proof_root: [6; 32],
        vrf_proof_root: [7; 32],
        active_validator_set_root: spec.genesis_validator_set_root,
        next_validator_set_root: spec.genesis_validator_set_root,
        da_root: [8; 32],
    }
}

fn engine_with_proof(spec: &ChainSpec) -> (Engine<FaultDb>, Chunk) {
    // Signed-session tests only: this receipt is never accepted by a prover or
    // a production finalization API.
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let header = crate::test_db::header(1, 1, spec.genesis_block_hash, ZERO_HASH);
    let hash = engine.store_mut().put_header(&header).unwrap();
    engine
        .commit_materialized_head(1, hash, ZERO_HASH, None)
        .unwrap();
    let public_inputs = neutrin0_consensus_types::BlockProofPublicInputs {
        context: Box::default(),
        chain_id: spec.chain_id,
        height: 1,
        parent_block_hash: spec.genesis_block_hash,
        block_hash: hash,
        state_root_before: ZERO_HASH,
        state_root_after: ZERO_HASH,
        transactions_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        da_root: ZERO_HASH,
        vm_code_hash: spec.runtime_code_hash,
        block_program: [0; 8],
        gas_used: 0,
        gas_limit: header.gas_limit,
        proposer_address: ZERO_HASH,
        runtime_extra: ZERO_HASH,
        inputs_root: [0; 32],
    };
    engine
        .store_mut()
        .put_block_proof(
            &hash,
            &neutrin0_consensus_types::BlockProof {
                prover_address: public_inputs.proposer_address,
                statement_key: [0; 32],
                height: 1,
                block_hash: hash,
                public_inputs,
                proof_bytes: vec![1],
            },
        )
        .unwrap();
    let mut candidate = chunk(spec);
    candidate.end_block_hash = hash;
    candidate.start_block_hash = hash;
    (engine, candidate)
}

fn peer_prevote(spec: &ChainSpec, candidate: &Chunk, index: u32) -> FinalityVote {
    let data = data(0, candidate.hash(), FinalityVotePhase::Prevote);
    let mut aggregation_bits = BitVec::default();
    for position in 0..3 {
        aggregation_bits.push(position == index);
    }
    FinalityVote {
        proof_manifests: Vec::new(),
        signature: key(index).sign_finality_vote(spec.consensus_domain(), &data),
        data: data.clone(),
        aggregation_bits,
        attestations: vec![key(index).attest_vote(
            spec.consensus_domain(),
            data.clone(),
            Vec::new(),
            None,
        )],
    }
}

fn open_signed_fixture<DB: Database>(
    engine: &mut Engine<DB>,
    candidate: Chunk,
    now: u64,
) -> Result<Vec<crate::BftAction>, crate::BftLoopError<DB::Error>> {
    // A local stake-weighted leader would sign its own selection; fixtures
    // install the fixed one whoever leads.
    let mut actions = engine.open_fixture_bft_session_at(candidate.clone(), now)?;
    if engine
        .bft_session(candidate.chunk_id)
        .unwrap()
        .proposal()
        .is_none()
    {
        let leader = neutrin0_consensus_types::bft_leader(
            engine.chain_spec().chain_id,
            candidate.chunk_id,
            0,
            &engine.finalized_seed(),
            engine.active_validator_set(),
        )
        .unwrap();
        // Fixture votes sign the fixed selection (`fixture_selection`).
        let mut proposal = BftProposal {
            chunk: candidate,
            round: 0,
            proposer_index: leader,
            valid_quorum: None,
            round_change_certificate: None,
            proposal_slot: 0,
            receipts: Vec::new(),
            ratified_chunk_proofs: Vec::new(),
            signature: [0; 96],
        };
        proposal.signature = key(leader)
            .sign_raw(&proposal.signing_message(engine.chain_spec().consensus_domain()))
            .to_bytes();
        actions.extend(engine.accept_authorized_bft_fixture(proposal, now)?);
    }
    Ok(actions)
}

fn distinct_spec_with_the_same_id() -> ChainSpec {
    let mut other = spec();
    other.genesis_block_hash[0] ^= 1;
    other.validate().unwrap();
    assert_eq!(other.chain_id, spec().chain_id);
    assert_ne!(other.hash(), spec().hash());
    other
}

#[test]
fn same_id_and_key_cannot_replay_foreign_spec_bft_messages_or_artifacts() {
    use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
    let local_spec = spec();
    let foreign_spec = distinct_spec_with_the_same_id();
    let (mut local, candidate) = engine_with_proof(&local_spec);
    local.open_bft_session_at(candidate.clone(), 0).unwrap();
    let foreign_vote = peer_prevote(&foreign_spec, &candidate, 0);
    assert!(local.verify_bft_value_vote(&foreign_vote).is_err());
    assert!(local.observe_finality_vote(foreign_vote.clone()).is_err());
    assert!(local.observe_votes_for_slashing(&foreign_vote).is_err());
    assert!(local.retain_signed_vote(&foreign_vote).is_err());

    let mut foreign = Engine::genesis(foreign_spec, MemoryDatabase::new()).unwrap();
    let nil = foreign
        .sign_nil_vote_durable(
            &key(0),
            NilVoteData {
                chunk_id: 0,
                round: 0,
                phase: FinalityVotePhase::Prevote,
            },
        )
        .unwrap();
    assert!(local.observe_nil_vote(nil.clone(), 0).is_err());
    assert!(local.observe_nil_votes_for_slashing(&nil).is_err());
    assert!(
        local
            .retain_signed_artifact(&SignedArtifact::NilVote(nil), false)
            .is_err()
    );
    let report = foreign
        .sign_round_change_durable(
            &key(0),
            RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: 0,
                highest_quorum: None,
                signature: [0; 96],
            },
        )
        .unwrap();
    assert!(local.observe_round_change(report.clone(), 0).is_err());
    assert!(
        local
            .retain_signed_artifact(&SignedArtifact::RoundChange(report), false)
            .is_err()
    );
    assert_eq!(local.bft_session(0).unwrap().round(), 0);
    assert_eq!(local.slashing_monitor.votes_tracked(), 0);
    assert!(local.store().signed_artifact_metadata().unwrap().is_empty());
}

#[test]
fn foreign_spec_nil_signature_cannot_fabricate_a_local_value_offence() {
    use neutrin0_consensus_types::{IndexedNilVote, IndexedVote, SlashingEvidence};
    let local_spec = spec();
    let local = Engine::genesis(local_spec.clone(), MemoryDatabase::new()).unwrap();
    let candidate = chunk(&local_spec);
    let value = peer_prevote(&local_spec, &candidate, 0);
    let nil_data = NilVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
    };
    let foreign_domain = distinct_spec_with_the_same_id().consensus_domain();
    let mut evidence = SlashingEvidence::ConflictingNilVote {
        validator_index: 0,
        value_vote: IndexedVote {
            data: value.data,
            signature: value.signature,
        },
        nil_vote: IndexedNilVote {
            data: nil_data.clone(),
            signature: key(0)
                .sign_raw(&nil_data.signing_message(foreign_domain))
                .to_bytes(),
        },
    };
    assert!(local.verify_slashing_evidence(&evidence).is_err());
    let SlashingEvidence::ConflictingNilVote { nil_vote, .. } = &mut evidence else {
        unreachable!();
    };
    nil_vote.signature = key(0)
        .sign_raw(&nil_data.signing_message(local_spec.consensus_domain()))
        .to_bytes();
    local.verify_slashing_evidence(&evidence).unwrap();
    let SlashingEvidence::ConflictingNilVote { value_vote, .. } = &mut evidence else {
        unreachable!();
    };
    value_vote.signature = key(0).sign_finality_vote(foreign_domain, &value_vote.data);
    assert!(local.verify_slashing_evidence(&evidence).is_err());
    assert_eq!(local.slashing_monitor.votes_tracked(), 0);
}

#[test]
fn reserved_round_report_recovery_rejects_a_changed_spec_domain_prefix() {
    let spec = spec();
    let voter = key(0);
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine
        .sign_round_change_durable(
            &voter,
            RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: 0,
                highest_quorum: None,
                signature: [0; 96],
            },
        )
        .unwrap();
    let storage_key = round_message_key(ROUND_CHANGE_MESSAGE_TAG, voter.public_key_bytes(), 0, 1);
    let bytes = engine
        .store()
        .db()
        .get(Column::SigningJournal, &storage_key)
        .unwrap()
        .unwrap();
    let mut intent: MessageIntent = borsh::from_slice(&bytes).unwrap();
    intent.message[SPEC_HASH_OFFSET..DOMAIN_PREFIX_LEN]
        .copy_from_slice(&distinct_spec_with_the_same_id().hash());
    let mut batch = Batch::new();
    batch.put(
        Column::SigningJournal,
        storage_key,
        borsh::to_vec(&intent).unwrap(),
    );
    engine
        .store_mut()
        .db_mut()
        .write_batch_durable(batch)
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert!(matches!(
        restarted.reserved_round_change(&voter, 0, 1),
        Err(EngineError::Store(StoreError::Corrupt(
            "round message reservation changed"
        )))
    ));
}

#[test]
fn vote_reservation_survives_restart_and_refuses_conflict_or_older_round() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let vote = engine
        .sign_vote_durable(
            &key(0),
            data(2, [1; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None,
        )
        .unwrap();
    let db = engine.store().db().clone();
    let mut restarted = Engine::open(spec, db).unwrap();
    assert_eq!(
        vote,
        restarted
            .sign_vote_durable(&key(0), vote.data.clone(), Vec::new(), None)
            .unwrap()
    );
    assert!(matches!(
        restarted.sign_vote_durable(
            &key(0),
            data(2, [2; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    assert!(matches!(
        restarted.sign_vote_durable(
            &key(0),
            data(1, [1; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
}

#[test]
fn full_attestation_and_key_identity_are_reserved() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let precommit = data(0, [1; 32], FinalityVotePhase::Precommit);
    let quorum = Some(quorum_for(&spec, precommit.clone()));
    engine
        .sign_vote_durable(&key(0), precommit.clone(), vec![[3; 32]], quorum.clone())
        .unwrap();
    assert!(matches!(
        engine.sign_vote_durable(&key(0), precommit.clone(), vec![[4; 32]], quorum.clone()),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    // A different public key has independent signing state; a reused index does not.
    assert!(
        engine
            .sign_vote_durable(&key(1), precommit.clone(), vec![[4; 32]], quorum.clone())
            .is_ok()
    );
    let wrong_index = ProposerKey::from_ikm(&[1; 32], 1).unwrap();
    assert!(matches!(
        engine.sign_vote_durable(&wrong_index, precommit, vec![[3; 32]], quorum),
        Err(EngineError::Signing(SigningViolation::KeyNotActive))
    ));
}

#[test]
fn failed_durable_reservation_returns_no_vote_and_keeps_journal_unchanged() {
    let mut engine = Engine::genesis(spec(), FaultDb::default()).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(0);
    assert!(
        engine
            .sign_vote_durable(
                &key(0),
                data(0, [1; 32], FinalityVotePhase::Prevote),
                Vec::new(),
                None
            )
            .is_err()
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    assert!(engine.bft_session(0).is_none());
}

#[test]
fn proposal_slot_watermark_survives_restart() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let signature = engine
        .sign_proposal_durable(&key(0), &header(15, 1))
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(
        signature,
        restarted
            .sign_proposal_durable(&key(0), &header(15, 1))
            .unwrap()
    );
    assert!(matches!(
        restarted.sign_proposal_durable(&key(0), &header(15, 2)),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    assert!(matches!(
        restarted.sign_proposal_durable(&key(0), &header(14, 1)),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
}

#[test]
fn active_position_rebinding_preserves_the_public_key_signing_journal() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0).with_validator_index(99));
    assert_eq!(engine.local_voter().unwrap().validator_index(), 0);
    let signature = engine
        .sign_proposal_durable(&key(0), &header(15, 1))
        .unwrap();
    let journal = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    // Unit harness: the snapshot setter exercises the same rebinding that
    // production performs when installing an authenticated consensus boundary.
    let mut active = spec.initial_validators.clone();
    active.swap(0, 2);
    engine.set_active_validator_set(1, active.clone()).unwrap();
    assert_eq!(engine.local_voter().unwrap().validator_index(), 2);
    let rebound = engine.active_local_voter().unwrap();
    assert_eq!(
        engine
            .sign_proposal_durable(&rebound, &header(15, 1))
            .unwrap(),
        signature
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        journal
    );
    let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
    restored.set_local_voter(key(0));
    assert_eq!(restored.local_voter().unwrap().validator_index(), 2);
    let rebound = restored.active_local_voter().unwrap();
    assert!(matches!(
        restored.sign_proposal_durable(&rebound, &header(15, 2)),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    assert!(matches!(
        restored.sign_proposal_durable(&rebound, &header(14, 1)),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
    let precommit = data(0, [1; 32], FinalityVotePhase::Precommit);
    let quorum = quorum_for(restored.chain_spec(), precommit.clone());
    let vote = restored
        .sign_vote_durable(&rebound, precommit, vec![[3; 32]], Some(quorum))
        .unwrap();
    assert_eq!(vote.aggregation_bits.get(2), Some(true));
    assert_eq!(vote.aggregation_bits.get(0), Some(false));
    assert_eq!(vote.attestations[0].validator_index, 2);
    neutrin0_prover_chunk::finality::verify_vote(
        restored.chain_spec().consensus_domain(),
        &active,
        &vote,
        &restored.chain_spec().consensus,
    )
    .unwrap();
}

#[test]
fn inactive_configured_key_waits_without_reserving_votes_or_proposals() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let inactive = key(99);
    engine.set_local_voter(inactive.clone());
    assert_eq!(
        engine.local_voter().unwrap().public_key_bytes(),
        inactive.public_key_bytes()
    );
    assert!(engine.active_local_voter().is_none());
    assert!(
        engine
            .try_produce_block(
                1,
                crate::ProductionConfig {
                    proposer: &inactive,
                },
                neutrin0_consensus_types::Body::default(),
                &neutrin0_proof_system::UnsupportedExecutor,
            )
            .unwrap()
            .is_none()
    );
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    let actions = engine
        .tick_bft_round_timeouts(100 + spec.consensus.bft_round_timeout_base_secs)
        .unwrap();
    assert!(actions.iter().all(|action| !matches!(
        action,
        crate::BftAction::BroadcastPrevote(_) | crate::BftAction::BroadcastPrecommit(_)
    )));
    engine.resume_bft_actions().unwrap();
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    assert_eq!(engine.head_height(), 0);
    {
        let mut active = spec.initial_validators;
        active[0].effective_stake = 0;
        engine.set_active_validator_set(1, active).unwrap();
        engine.set_local_voter(key(0));
        assert!(engine.active_local_voter().is_none());
        assert!(
            engine
                .try_produce_block(
                    1,
                    crate::ProductionConfig { proposer: &key(0) },
                    neutrin0_consensus_types::Body::default(),
                    &neutrin0_proof_system::UnsupportedExecutor,
                )
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn session_restart_preserves_phase_clock_and_original_value_and_nil_votes() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    let next = engine
        .tick_bft_round_timeouts(100 + spec.consensus.bft_round_timeout_base_secs)
        .unwrap();
    let original = next
        .iter()
        .find_map(|action| match action {
            crate::BftAction::BroadcastNilVote(vote) => Some(vote.clone()),
            _ => None,
        })
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    assert_eq!(restarted.bft_session(0).unwrap().round(), 0);
    assert_eq!(
        restarted.bft_session(0).unwrap().round_started_at_secs(),
        engine.bft_session(0).unwrap().round_started_at_secs()
    );
    let resumed = restarted.resume_bft_actions().unwrap();
    assert!(resumed.iter().any(
        |action| matches!(action, crate::BftAction::BroadcastNilVote(vote)
        if *vote == original)
    ));
    assert!(
        resumed
            .iter()
            .any(|action| matches!(action, crate::BftAction::BroadcastPrevote(_)))
    );
}

#[test]
fn crash_after_vote_intent_before_session_commit_recovers_original_vote() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    // Keep the real signed proposal durable before injecting the reservation gap.
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    engine.set_local_voter(key(0));
    engine.store_mut().db_mut().fail_durable_after = Some(1);
    assert!(
        engine
            .sign_vote_durable(
                &key(0),
                data(0, chunk(&spec).hash(), FinalityVotePhase::Prevote),
                Vec::new(),
                None
            )
            .is_err()
    );
    assert!(!engine.bft_session(0).unwrap().local_prevoted());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::BftSessions)
            .unwrap()
            .len(),
        1
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    restarted.set_local_voter(key(0));
    let actions = restarted.resume_bft_actions().unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, crate::BftAction::BroadcastPrevote(_)))
    );
    let mut conflicting = chunk(&spec);
    conflicting.end_state_root = [99; 32];
    assert!(restarted.open_bft_session_at(conflicting, 102).is_err());
}

#[test]
fn crash_during_certified_round_entry_restores_unsigned_phase_before_signing() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    let reports = (0..3)
        .map(|index| {
            let mut report = RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: index,
                highest_quorum: None,
                signature: [0; 96],
            };
            report.signature = key(index)
                .sign_raw(&report.signing_message(spec.consensus_domain()))
                .to_bytes();
            report
        })
        .collect();
    let certificate = neutrin0_consensus_types::RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports,
    };
    engine.store_mut().db_mut().fail_durable_after = Some(1);
    assert!(
        engine
            .observe_round_change_certificate(certificate.clone(), 110)
            .is_err()
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec, db).unwrap();
    restarted.set_local_voter(key(0));
    restarted.resume_bft_actions().unwrap();
    assert_eq!(restarted.bft_session(0).unwrap().round(), 1);
    assert_eq!(
        restarted.bft_session(0).unwrap().round_change_certificate(),
        Some(&certificate)
    );
    assert_eq!(
        restarted.bft_session(0).unwrap().round_started_at_secs(),
        110
    );
}

#[test]
fn finalized_floor_prevents_resigning_after_journal_gc() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine
        .sign_vote_durable(
            &key(0),
            data(0, [1; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None,
        )
        .unwrap();
    // Exercise the signing floor independently of proof finalization fixtures.
    engine.store_mut().put_latest_finalized_chunk_id(0).unwrap();
    let mut batch = Batch::new();
    engine.expired_signing_entries(&mut batch).unwrap();
    engine
        .store_mut()
        .db_mut()
        .write_batch_durable(batch)
        .unwrap();
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    assert!(matches!(
        engine.sign_vote_durable(
            &key(0),
            data(0, [2; 32], FinalityVotePhase::Prevote),
            Vec::new(),
            None
        ),
        Err(EngineError::Signing(SigningViolation::FinalizedChunk))
    ));
}

#[test]
fn crash_after_precommit_reservation_recovers_original_unlock_quorum() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(3);
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
            .is_err()
    );
    assert!(!engine.bft_session(0).unwrap().local_precommitted());
    let saved = engine
        .store()
        .db()
        .get(
            Column::SigningJournal,
            &vote_key(key(0).public_key_bytes(), 0),
        )
        .unwrap()
        .unwrap();
    let watermark: VoteWatermark = borsh::from_slice(&saved).unwrap();
    let original_unlock = watermark.precommit.unwrap().unlock_quorum.unwrap();
    engine.store_mut().db_mut().fail_durable_after = None;
    engine
        .set_local_signing_policy(LocalSigningPolicy {
            signing_paused: true,
            production_paused: false,
        })
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    let journal = restarted
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    restarted.resume_bft_actions().unwrap();
    assert_eq!(
        restarted.bft_session(0).unwrap().highest_lock_quorum(),
        Some(&original_unlock)
    );
    assert!(!restarted.bft_session(0).unwrap().local_precommitted());
    assert_eq!(
        journal,
        restarted
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap()
    );
    restarted
        .set_local_signing_policy(LocalSigningPolicy::default())
        .unwrap();
    let actions = restarted.resume_bft_actions().unwrap();
    let resumed = actions
        .iter()
        .find_map(|action| match action {
            crate::BftAction::BroadcastPrecommit(vote) => Some(vote),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        resumed.attestations[0].unlock_quorum,
        Some(original_unlock.clone())
    );
    assert_eq!(
        restarted.bft_session(0).unwrap().highest_lock_quorum(),
        Some(&original_unlock)
    );
}

#[test]
fn in_process_retry_does_not_change_reserved_unlock_claim_when_quorum_grows() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(3);
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
            .is_err()
    );
    let saved = engine
        .store()
        .db()
        .get(
            Column::SigningJournal,
            &vote_key(key(0).public_key_bytes(), 0),
        )
        .unwrap()
        .unwrap();
    let watermark: VoteWatermark = borsh::from_slice(&saved).unwrap();
    let original_unlock = watermark.precommit.unwrap().unlock_quorum.unwrap();
    engine.store_mut().db_mut().fail_durable_after = None;
    let actions = engine
        .observe_finality_vote(peer_prevote(&spec, &candidate, 2))
        .unwrap();
    let resumed = actions
        .iter()
        .find_map(|action| match action {
            crate::BftAction::BroadcastPrecommit(vote) => Some(vote),
            _ => None,
        })
        .unwrap();
    assert_eq!(resumed.attestations[0].unlock_quorum, Some(original_unlock));
    assert!(engine.bft_session(0).unwrap().local_precommitted());
}

#[test]
fn restart_with_changed_receipts_opens_and_attests_those_held_when_signing() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    let mut receipt = engine
        .store()
        .get_block_proof(&candidate.end_block_hash)
        .unwrap()
        .unwrap();
    receipt.proof_bytes.push(2);
    // Held receipts change before this node precommits (a proposer's late
    // receipt replaces the preferred one); here both the preferred receipt
    // and the retained receipt under the named key change.
    let stored = crate::store::StoredReceipt {
        proof: receipt.clone(),
        first_verified_slot: 0,
    };
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::BlockReceipts,
            &crate::store::receipt_key(&candidate.end_block_hash, &receipt.statement_key),
            &borsh::to_vec(&stored).unwrap(),
        )
        .unwrap();
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::BlockProofs,
            &candidate.end_block_hash,
            &borsh::to_vec(&receipt).unwrap(),
        )
        .unwrap();
    // Nothing was signed over the old receipts, so the node opens and its
    // precommit attests the receipts it holds when signing.
    let mut restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    restarted.resume_bft_actions().unwrap();
    let actions = restarted
        .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
        .unwrap();
    let precommit = actions
        .iter()
        .find_map(|action| match action {
            crate::BftAction::BroadcastPrecommit(vote) => Some(vote),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        precommit.proof_manifests,
        vec![ProofManifest {
            proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(&receipt)],
        }]
    );
}

#[test]
fn unfinished_session_rejects_key_replacement_consistently() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    engine.set_local_voter(key(1));
    assert!(engine.resume_bft_actions().is_err());
    assert!(
        engine
            .tick_bft_round_timeouts(100 + spec.consensus.bft_round_timeout_base_secs)
            .is_err()
    );
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &chunk(&spec), 2))
            .is_err()
    );
}

#[test]
fn certified_round_entry_recovers_the_signing_identity_before_leader_signing() {
    let spec = spec();
    let next_leader = neutrin0_consensus_types::bft_leader(
        spec.chain_id,
        0,
        1,
        &spec.genesis_seed,
        &spec.initial_validators,
    )
    .unwrap();
    let original = (next_leader + 1) % 3;
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(original));
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    assert!(engine.bft_session(0).unwrap().local_prevoted());
    // The replacement key leads round one: entering it unrecovered would sign
    // a proposal and prevote into a session holding another key's votes.
    engine.set_local_voter(key(next_leader));
    let reports: Vec<_> = (0..3)
        .map(|index| {
            let mut report = RoundChange {
                chunk_id: 0,
                round: 1,
                validator_index: index,
                highest_quorum: None,
                signature: [0; 96],
            };
            report.signature = key(index)
                .sign_raw(&report.signing_message(spec.consensus_domain()))
                .to_bytes();
            report
        })
        .collect();
    let journal = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    let certificate = neutrin0_consensus_types::RoundChangeCertificate {
        chunk_id: 0,
        round: 1,
        reports: reports.clone(),
    };
    assert!(
        engine
            .observe_round_change_certificate(certificate, 110)
            .is_err()
    );
    for report in reports {
        assert!(engine.observe_round_change(report, 110).is_err());
    }
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        journal
    );
}

#[test]
fn corrupt_watermark_cannot_reauthorize_an_altered_attestation() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    engine
        .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
        .unwrap();
    let journal_key = vote_key(key(0).public_key_bytes(), 0);
    let saved = engine
        .store()
        .db()
        .get(Column::SigningJournal, &journal_key)
        .unwrap()
        .unwrap();
    let mut watermark: VoteWatermark = borsh::from_slice(&saved).unwrap();
    watermark
        .precommit
        .as_mut()
        .unwrap()
        .proof_acceptance
        .as_mut()
        .unwrap()
        .root = [99; 32];
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::SigningJournal,
            &journal_key,
            &borsh::to_vec(&watermark).unwrap(),
        )
        .unwrap();
    let before = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    assert!(restarted.resume_bft_actions().is_err());
    assert_eq!(
        before,
        restarted
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap()
    );
}

#[test]
fn direct_finalization_recovers_existing_session_without_prior_node_resume() {
    let spec = spec();
    let (mut engine, candidate) = engine_with_proof(&spec);
    engine.set_local_voter(key(0));
    open_signed_fixture(&mut engine, candidate.clone(), 100).unwrap();
    let proof = engine
        .store()
        .get_block_proof(&candidate.end_block_hash)
        .unwrap()
        .unwrap();
    let mut peer = peer_prevote(&spec, &candidate, 1);
    peer.data.phase = FinalityVotePhase::Precommit;
    peer.signature = key(1).sign_finality_vote(spec.consensus_domain(), &peer.data);
    peer.proof_manifests = vec![ProofManifest {
        proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(&proof)],
    }];
    peer.attestations = vec![key(1).attest_vote(
        spec.consensus_domain(),
        peer.data.clone(),
        peer.proof_manifests[0].proof_hashes.clone(),
        None,
    )];
    engine.observe_finality_vote(peer).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(3);
    assert!(
        engine
            .observe_finality_vote(peer_prevote(&spec, &candidate, 1))
            .is_err()
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    assert!(restarted.local_voter().is_none());
    let certificate = restarted
        .run_chunk_bft(
            &candidate,
            candidate.hash(),
            &key(0),
            spec.genesis_validator_set_root,
        )
        .unwrap();
    neutrin0_prover_chunk::finality::verify_finality(
        spec.consensus_domain(),
        &spec.consensus,
        &spec.initial_validators,
        &spec.genesis_seed,
        &candidate,
        &certificate,
    )
    .unwrap();
    assert!(restarted.local_voter().is_none());
    assert!(restarted.bft_session(0).unwrap().local_precommitted());
}

#[test]
fn durable_lock_rejects_circular_prevotes_and_survives_an_unsigned_new_round() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let first = data(0, [1; 32], FinalityVotePhase::Precommit);
    let locked = quorum_for(&spec, first.clone());
    engine
        .sign_vote_durable(&key(0), first, vec![[3; 32]], Some(locked.clone()))
        .unwrap();
    let mut target = data(1, [2; 32], FinalityVotePhase::Prevote);
    assert!(
        engine
            .sign_vote_durable(&key(0), target.clone(), vec![], None)
            .is_err()
    );
    let justification = quorum_for(&spec, target.clone());
    assert!(
        engine
            .sign_vote_durable(&key(0), target.clone(), vec![], Some(justification.clone()))
            .is_err()
    );
    target.round = 2;
    let signed = engine
        .sign_vote_durable(&key(0), target.clone(), vec![], Some(justification.clone()))
        .unwrap();
    assert_eq!(
        signed.attestations[0].unlock_quorum,
        Some(justification.clone())
    );
    let mut restored = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(reserved_lock(&restored), Some(locked));
    assert_eq!(
        restored
            .sign_vote_durable(&key(0), target.clone(), vec![], Some(justification))
            .unwrap(),
        signed
    );
    assert!(
        restored
            .sign_vote_durable(&key(0), target, vec![], None)
            .is_err()
    );
}

#[test]
fn restart_completes_a_durable_authorized_proposal_before_first_vote_reservation() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    open_signed_fixture(&mut engine, chunk(&spec), 100).unwrap();
    assert!(!engine.bft_session(0).unwrap().local_prevoted());
    let original = engine.bft_session(0).unwrap().proposal().unwrap().clone();
    let mut restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
    restarted.set_local_voter(key(0));
    let actions = restarted.resume_bft_actions().unwrap();
    assert!(actions.iter().any(
        |action| matches!(action, crate::BftAction::BroadcastPrevote(vote)
        if vote.data.chunk_hash == original.chunk.hash())
    ));
    assert_eq!(
        restarted.bft_session(0).unwrap().proposal(),
        Some(&original)
    );
    Engine::open(spec, restarted.store().db().clone()).unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Walks several rounds of nil votes and checks every retained journal entry."
)]
fn repeated_nil_rounds_compact_intents_and_preserve_the_exact_retained_lock() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let locked_data = data(0, [1; 32], FinalityVotePhase::Precommit);
    let locked = quorum_for(&spec, locked_data.clone());
    let original = engine
        .sign_vote_durable(
            &key(0),
            locked_data.clone(),
            vec![[3; 32]],
            Some(locked.clone()),
        )
        .unwrap();
    for round in 1..=200 {
        for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
            engine
                .sign_nil_vote_durable(
                    &key(0),
                    NilVoteData {
                        chunk_id: 0,
                        round,
                        phase,
                    },
                )
                .unwrap();
        }
        engine
            .sign_round_change_durable(
                &key(0),
                RoundChange {
                    chunk_id: 0,
                    round: round + 1,
                    validator_index: 0,
                    highest_quorum: Some(locked.clone()),
                    signature: [0; 96],
                },
            )
            .unwrap();
        assert!(engine.store().db().len(Column::SigningJournal) <= 7);
    }
    let bytes = engine
        .store()
        .db()
        .get(
            Column::SigningJournal,
            &intent_key(key(0).public_key_bytes(), &locked_data),
        )
        .unwrap()
        .unwrap();
    let retained: VoteIntent = borsh::from_slice(&bytes).unwrap();
    assert_eq!(
        retained.proof_acceptance,
        original.attestations[0].proof_acceptance
    );
    assert_eq!(
        engine
            .reserved_proof_manifest(key(0).public_key_bytes(), &retained)
            .unwrap()
            .unwrap(),
        original.proof_manifests[0]
    );
    assert_eq!(retained.unlock_quorum, Some(locked.clone()));
    let mut restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
    assert_eq!(reserved_lock(&restarted), Some(locked));
    assert!(matches!(
        restarted.sign_nil_vote_durable(
            &key(0),
            NilVoteData {
                chunk_id: 0,
                round: 1,
                phase: FinalityVotePhase::Prevote,
            }
        ),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
    let latest_data = data(201, [1; 32], FinalityVotePhase::Precommit);
    let latest = quorum_for(&spec, latest_data.clone());
    restarted
        .sign_vote_durable(&key(0), latest_data, vec![[4; 32]], Some(latest.clone()))
        .unwrap();
    assert!(
        restarted
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &intent_key(key(0).public_key_bytes(), &locked_data),
            )
            .unwrap()
            .is_none()
    );
    let old_manifest_key = manifest_key(
        key(0).public_key_bytes(),
        0,
        &original.attestations[0].proof_acceptance.unwrap(),
    );
    assert!(
        restarted
            .store()
            .db()
            .get(Column::SigningJournal, &old_manifest_key)
            .unwrap()
            .is_none()
    );
    let restored = Engine::open(spec, restarted.store().db().clone()).unwrap();
    assert_eq!(reserved_lock(&restored), Some(latest));
}

#[test]
fn failed_compaction_atomically_preserves_the_previous_reservation_and_lock() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let initial = data(0, [1; 32], FinalityVotePhase::Precommit);
    let locked = quorum_for(&spec, initial.clone());
    let original = engine
        .sign_vote_durable(
            &key(0),
            initial.clone(),
            vec![[3; 32]],
            Some(locked.clone()),
        )
        .unwrap();
    let before = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(0);
    let nil = NilVoteData {
        chunk_id: 0,
        round: 1,
        phase: FinalityVotePhase::Prevote,
    };
    assert!(engine.sign_nil_vote_durable(&key(0), nil.clone()).is_err());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        before
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec, db).unwrap();
    assert_eq!(
        restarted
            .sign_vote_durable(&key(0), initial, vec![[3; 32]], Some(locked.clone()))
            .unwrap(),
        original
    );
    restarted.sign_nil_vote_durable(&key(0), nil).unwrap();
    assert_eq!(reserved_lock(&restarted), Some(locked));
}

#[test]
fn message_only_rounds_remain_bounded_after_interrupted_artifact_retention() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let mut latest = None;
    for round in 1..=100 {
        let report = RoundChange {
            chunk_id: 0,
            round: round * 10,
            validator_index: 0,
            highest_quorum: None,
            signature: [0; 96],
        };
        // The signature reservation commits; artifact publication fails before
        // any vote watermark exists for this skipped round.
        engine.store_mut().db_mut().fail_durable_after = Some(1);
        assert!(
            engine
                .sign_round_change_durable(&key(0), report.clone())
                .is_err()
        );
        assert_eq!(
            engine
                .store()
                .db()
                .iter_column(Column::SigningJournal)
                .unwrap()
                .len(),
            2
        );
        latest = Some(report);
    }
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    let report = latest.unwrap();
    let signed = restarted
        .reserved_round_change(&key(0), 0, report.round)
        .unwrap()
        .unwrap();
    assert_eq!(
        signed.signing_message(spec.consensus_domain()),
        report.signing_message(spec.consensus_domain())
    );
    assert!(matches!(
        restarted.sign_round_change_durable(
            &key(0),
            RoundChange {
                round: 1,
                ..report.clone()
            }
        ),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
    let before = restarted
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    restarted.store_mut().db_mut().fail_durable_after = Some(0);
    assert!(
        restarted
            .sign_round_change_durable(
                &key(0),
                RoundChange {
                    round: report.round + 1,
                    ..report
                }
            )
            .is_err()
    );
    assert_eq!(
        restarted
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        before
    );
    let mut db = restarted.store().db().clone();
    db.fail_durable_after = None;
    let mut recovered = Engine::open(spec, db).unwrap();
    assert_eq!(
        recovered
            .reserved_round_change(&key(0), 0, signed.round)
            .unwrap(),
        Some(signed)
    );
}

#[test]
fn exact_manifest_is_stored_once_and_reconstructed_after_restart() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let voter = key(0);
    let mut latest = None;
    for round in 0..4 {
        let vote_data = data(round, [1; 32], FinalityVotePhase::Precommit);
        let quorum = quorum_for(&spec, vote_data.clone());
        latest = Some(
            engine
                .sign_vote_durable(&voter, vote_data, vec![[3; 32]], Some(quorum))
                .unwrap(),
        );
        let manifests = engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap()
            .into_iter()
            .filter(|(key, _)| key.first() == Some(&PROOF_MANIFEST_TAG))
            .count();
        assert_eq!(manifests, 1);
    }
    let latest = latest.unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    let progress = restarted
        .reserved_signing_progress(&voter, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        restarted.reserved_local_votes(&voter, &progress).unwrap(),
        vec![latest]
    );
}

#[test]
fn missing_or_changed_reserved_manifest_cannot_reauthorize_signing() {
    for remove in [false, true] {
        let spec = spec();
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
        let voter = key(0);
        let vote_data = data(0, [1; 32], FinalityVotePhase::Precommit);
        let quorum = quorum_for(&spec, vote_data.clone());
        let original = engine
            .sign_vote_durable(&voter, vote_data, vec![[3; 32]], Some(quorum))
            .unwrap();
        let acceptance = original.attestations[0].proof_acceptance.unwrap();
        let key = manifest_key(voter.public_key_bytes(), 0, &acceptance);
        if remove {
            engine
                .store_mut()
                .db_mut()
                .delete(Column::SigningJournal, &key)
                .unwrap();
        } else {
            let changed = ProofManifest {
                proof_hashes: vec![[4; 32]],
            };
            engine
                .store_mut()
                .db_mut()
                .put(
                    Column::SigningJournal,
                    &key,
                    &borsh::to_vec(&changed).unwrap(),
                )
                .unwrap();
        }
        let restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
        assert!(restarted.reserved_signing_progress(&voter, 0).is_err());
    }
}

#[test]
fn manifest_and_compact_reservation_commit_atomically() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let voter = key(0);
    let vote_data = data(0, [1; 32], FinalityVotePhase::Precommit);
    let quorum = quorum_for(&spec, vote_data.clone());
    let before = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(0);
    assert!(
        engine
            .sign_vote_durable(
                &voter,
                vote_data.clone(),
                vec![[3; 32]],
                Some(quorum.clone())
            )
            .is_err()
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        before
    );
    engine.store_mut().db_mut().fail_durable_after = None;
    let original = engine
        .sign_vote_durable(&voter, vote_data, vec![[3; 32]], Some(quorum))
        .unwrap();
    let mut altered = original.clone();
    altered.proof_manifests[0].proof_hashes[0] = [4; 32];
    assert!(
        engine
            .verify_saved_local_vote(*voter.public_key_bytes(), &altered)
            .is_err()
    );
    assert!(
        engine
            .verify_saved_local_vote(*voter.public_key_bytes(), &original)
            .is_ok()
    );
}

#[test]
fn typed_proposal_and_report_carriers_recover_exactly_after_interrupted_publication() {
    let spec = spec();
    let original = proposal_with_carriers(&spec, 1);
    let voter = key(original.proposer_index);
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    // Reservation commits atomically, then signed source publication fails.
    engine.store_mut().db_mut().fail_durable_after = Some(1);
    assert!(
        engine
            .sign_bft_proposal_durable(&voter, original.clone())
            .is_err()
    );
    let storage_key = round_message_key(PROPOSAL_MESSAGE_TAG, voter.public_key_bytes(), 0, 1);
    let saved: MessageIntent = borsh::from_slice(
        &engine
            .store()
            .db()
            .get(Column::SigningJournal, &storage_key)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let MessageCarrier::Proposal(carrier) = saved.carrier else {
        panic!("proposal carrier kind");
    };
    assert_eq!(*carrier, original);
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    let recovered = restarted
        .reserved_bft_proposal(&voter, 0, 1)
        .unwrap()
        .unwrap();
    let mut expected = original.clone();
    expected.signature = voter
        .sign_raw(&expected.signing_message(spec.consensus_domain()))
        .to_bytes();
    assert_eq!(recovered, expected);
    assert_eq!(recovered.valid_quorum, original.valid_quorum);
    assert_eq!(
        recovered.round_change_certificate,
        original.round_change_certificate
    );

    let unsigned_report = RoundChange {
        chunk_id: 0,
        round: 2,
        validator_index: 0,
        highest_quorum: original.valid_quorum,
        signature: [0; 96],
    };
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    engine.store_mut().db_mut().fail_durable_after = Some(1);
    assert!(
        engine
            .sign_round_change_durable(&key(0), unsigned_report.clone())
            .is_err()
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec.clone(), db).unwrap();
    let recovered = restarted
        .reserved_round_change(&key(0), 0, 2)
        .unwrap()
        .unwrap();
    let mut expected = unsigned_report;
    expected.signature = key(0)
        .sign_raw(&expected.signing_message(spec.consensus_domain()))
        .to_bytes();
    assert_eq!(recovered, expected);
}

#[test]
fn changed_typed_carriers_cannot_recover_a_reserved_compact_message() {
    let spec = spec();
    for mutation in 0..4 {
        let original = proposal_with_carriers(&spec, 1);
        let voter = key(original.proposer_index);
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
        engine.sign_bft_proposal_durable(&voter, original).unwrap();
        let storage_key = round_message_key(PROPOSAL_MESSAGE_TAG, voter.public_key_bytes(), 0, 1);
        let saved = engine
            .store()
            .db()
            .get(Column::SigningJournal, &storage_key)
            .unwrap()
            .unwrap();
        let mut intent: MessageIntent = borsh::from_slice(&saved).unwrap();
        match mutation {
            0 => {
                let MessageCarrier::Proposal(carrier) = &mut intent.carrier else {
                    unreachable!();
                };
                carrier.valid_quorum.as_mut().unwrap().aggregate.signature[0] ^= 1;
            }
            1 => {
                let MessageCarrier::Proposal(carrier) = &mut intent.carrier else {
                    unreachable!();
                };
                carrier.round_change_certificate.as_mut().unwrap().reports[0].signature[0] ^= 1;
            }
            2 => {
                // The carrier's own signature is normalized to zero before
                // reservation; it is not part of the compact signing message.
                let MessageCarrier::Proposal(carrier) = &mut intent.carrier else {
                    unreachable!();
                };
                carrier.signature[0] = 1;
            }
            _ => {
                intent.carrier = MessageCarrier::RoundChange(Box::new(RoundChange {
                    chunk_id: 0,
                    round: 1,
                    validator_index: voter.validator_index(),
                    highest_quorum: None,
                    signature: [0; 96],
                }));
            }
        }
        engine
            .store_mut()
            .db_mut()
            .put(
                Column::SigningJournal,
                &storage_key,
                &borsh::to_vec(&intent).unwrap(),
            )
            .unwrap();
        let mut restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
        assert!(matches!(
            restarted.reserved_bft_proposal(&voter, 0, 1),
            Err(EngineError::Store(StoreError::Corrupt(
                "round signing carrier changed"
            )))
        ));
    }
}

#[test]
fn failed_typed_carrier_compaction_keeps_original_source_and_watermark_atomic() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let original = proposal_with_carriers(&spec, 1);
    let voter = key(original.proposer_index);
    let original = engine.sign_bft_proposal_durable(&voter, original).unwrap();
    let before = engine
        .store()
        .db()
        .iter_column(Column::SigningJournal)
        .unwrap();
    // A full fair-leader cycle returns this same identity to its turn.
    let replacement = proposal_with_carriers(&spec, 4);
    assert_eq!(replacement.proposer_index, voter.validator_index());
    engine.store_mut().db_mut().fail_durable_after = Some(0);
    assert!(
        engine
            .sign_bft_proposal_durable(&voter, replacement.clone())
            .is_err()
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap(),
        before
    );
    let mut db = engine.store().db().clone();
    db.fail_durable_after = None;
    let mut restarted = Engine::open(spec, db).unwrap();
    assert_eq!(
        restarted.reserved_bft_proposal(&voter, 0, 1).unwrap(),
        Some(original.clone())
    );
    restarted
        .sign_bft_proposal_durable(&voter, replacement)
        .unwrap();
    assert!(
        restarted
            .reserved_bft_proposal(&voter, 0, 1)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        restarted.sign_bft_proposal_durable(&voter, original),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
}

#[test]
fn changed_report_quorum_carrier_cannot_recover_the_same_reserved_message() {
    let spec = spec();
    let voter = key(0);
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    let report = RoundChange {
        chunk_id: 0,
        round: 1,
        validator_index: 0,
        highest_quorum: Some(quorum_for(
            &spec,
            data(0, chunk(&spec).hash(), FinalityVotePhase::Prevote),
        )),
        signature: [0; 96],
    };
    engine.sign_round_change_durable(&voter, report).unwrap();
    let storage_key = round_message_key(ROUND_CHANGE_MESSAGE_TAG, voter.public_key_bytes(), 0, 1);
    let saved = engine
        .store()
        .db()
        .get(Column::SigningJournal, &storage_key)
        .unwrap()
        .unwrap();
    let mut intent: MessageIntent = borsh::from_slice(&saved).unwrap();
    let MessageCarrier::RoundChange(carrier) = &mut intent.carrier else {
        unreachable!();
    };
    carrier.highest_quorum.as_mut().unwrap().aggregate.signature[0] ^= 1;
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::SigningJournal,
            &storage_key,
            &borsh::to_vec(&intent).unwrap(),
        )
        .unwrap();
    let mut restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert!(matches!(
        restarted.reserved_round_change(&voter, 0, 1),
        Err(EngineError::Store(StoreError::Corrupt(
            "round signing carrier changed"
        )))
    ));
}

/// After a hard fork the successor specification keeps its predecessor's
/// signing domain only to verify old signatures; it never signs a chunk
/// below its fork, which would sign under that predecessor domain.
#[test]
fn a_forked_specification_never_signs_a_predecessor_chunk() {
    let mut engine = Engine::genesis(fork_of([3; 32]), MemoryDatabase::new()).unwrap();
    for chunk_id in [0, 1] {
        assert!(matches!(
            engine.sign_nil_vote_durable(
                &key(0),
                NilVoteData {
                    chunk_id,
                    round: 0,
                    phase: FinalityVotePhase::Prevote,
                },
            ),
            Err(EngineError::Signing(SigningViolation::PriorDomain))
        ));
    }
    // The successor's own chunks bind its own specification hash; older
    // chunks verify under the predecessor's.
    let nil = |chunk_id| NilVoteData {
        chunk_id,
        round: 0,
        phase: FinalityVotePhase::Prevote,
    };
    let domain = engine.consensus_domain();
    assert_eq!(
        &nil(2).signing_message(domain)[24..56],
        &engine.chain_spec_hash()
    );
    assert_eq!(&nil(1).signing_message(domain)[24..56], &[3; 32]);
}

/// [`spec`] as the hard-fork successor of `predecessor` at chunk 2.
fn fork_of(predecessor: Hash) -> ChainSpec {
    let mut forked = spec();
    let chunk_size = forked.consensus.chunk_size;
    let start = neutrin0_consensus_types::history_proof::ConsensusBoundary {
        next_chunk_id: 2,
        height: 2 * chunk_size,
        programs: forked.genesis_programs(),
        ..neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&forked)
    };
    forked.fork = Some(alloc::boxed::Box::new(neutrin0_primitives::ForkAnchor {
        predecessor,
        count: 2,
        endpoint_programs: start.programs,
        start,
        endpoint_prover: neutrin0_primitives::runtime_account([5; 20]),
        prior_domains: alloc::vec![neutrin0_primitives::PriorDomain {
            chain_spec_hash: predecessor,
            end_chunk: 2,
            end_height: 2 * chunk_size,
        }],
    }));
    forked.validate().unwrap();
    forked
}

/// Finalized state whose boundary carries a hard fork at `count`, as the
/// boundaries after governance scheduled one do.
fn schedule_fork(engine: &mut Engine<MemoryDatabase>, count: u64) {
    let spec = engine.chain_spec().clone();
    let fork = Some(neutrin0_primitives::ScheduledFork {
        count,
        successor: [7; 32],
    });
    let mut next_context =
        neutrin0_prover_chunk::consensus::genesis_context(&spec, spec.genesis_programs());
    next_context.fork = fork;
    let state = crate::full_chunk::ConsensusState {
        boundary: neutrin0_consensus_types::history_proof::ConsensusBoundary {
            fork,
            ..neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&spec)
        },
        next_context,
        next_seed: spec.genesis_seed,
        frontier: neutrin0_consensus_types::history::HistoryFrontier::default(),
    };
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::Finalized,
            crate::pointers::CONSENSUS_STATE,
            &borsh::to_vec(&state).unwrap(),
        )
        .unwrap();
}

/// A predecessor's validators stop signing at the count of the hard fork
/// governance scheduled and carry only their proposer slot watermarks to the
/// successor, so no slot they proposed at can carry a second header there.
#[test]
fn a_halted_predecessor_hands_its_slot_watermarks_to_the_successor() {
    let predecessor = spec();
    let nil = |chunk_id| NilVoteData {
        chunk_id,
        round: 0,
        phase: FinalityVotePhase::Prevote,
    };
    let mut engine = Engine::genesis(predecessor.clone(), MemoryDatabase::new()).unwrap();
    schedule_fork(&mut engine, 1);
    engine.sign_nil_vote_durable(&key(0), nil(0)).unwrap();
    assert!(matches!(
        engine.sign_nil_vote_durable(&key(0), nil(1)),
        Err(EngineError::Signing(SigningViolation::Halted))
    ));
    engine
        .sign_proposal_durable(&key(0), &header(3, 1))
        .unwrap();

    let transfer = crate::signing_transfer::SigningTransfer::export(engine.store().db()).unwrap();
    assert!(transfer.for_successor(&predecessor).is_err());
    assert!(transfer.for_successor(&fork_of([3; 32])).is_err());
    let successor = fork_of(predecessor.hash());
    let moved = transfer.for_successor(&successor).unwrap();
    assert_eq!(moved.chain_spec_hash, successor.hash());
    assert_eq!(moved.journal.len(), 1);
    let mut target = MemoryDatabase::new();
    moved.import(&mut target).unwrap();
    let mut successor = Engine::genesis(successor, target).unwrap();
    assert!(matches!(
        successor.sign_proposal_durable(&key(0), &header(3, 2)),
        Err(EngineError::Signing(SigningViolation::Conflict))
    ));
    assert!(matches!(
        successor.sign_proposal_durable(&key(0), &header(2, 2)),
        Err(EngineError::Signing(SigningViolation::Regression))
    ));
    successor
        .sign_proposal_durable(&key(0), &header(4, 2))
        .unwrap();
}

/// A header at `slot`; `variant` tells two headers of one slot apart.
fn header(slot: Slot, variant: u8) -> neutrin0_consensus_types::Header {
    neutrin0_consensus_types::Header {
        height: slot,
        slot,
        parent_hash: [variant; 32],
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
    }
}

/// After startup a validator signs nothing for its quiet period, so a twin
/// signing with its key shows itself first; a message by its key that its
/// journal did not reserve pauses signing and production durably.
#[test]
fn a_quiet_start_and_a_foreign_signature_keep_the_key_from_signing() {
    let nil = |round| NilVoteData {
        chunk_id: 0,
        round,
        phase: FinalityVotePhase::Prevote,
    };
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    engine.set_wall_clock(|| 1_800_000_000);
    engine.set_doppelganger_quiet_chunks(2);
    assert!(matches!(
        engine.sign_nil_vote_durable(&key(0), nil(0)),
        Err(EngineError::Signing(SigningViolation::Quiet))
    ));
    assert!(!engine.local_production_enabled());
    engine.set_wall_clock(|| 1_800_001_000);
    let own = engine.sign_nil_vote_durable(&key(0), nil(0)).unwrap();

    // The node's own message, relayed back, is its own.
    engine.observe_nil_votes_for_slashing(&own).unwrap();
    assert_eq!(engine.doppelganger(), None);
    // The same key at a round this journal never signed is another signer.
    let domain = engine.consensus_domain();
    let mut claim = NilVoteAttestation {
        validator_index: 0,
        vote: nil(3),
        vote_signature: [0; 96],
        signature: [0; 96],
    };
    let signatures = key(0)
        .sign(domain, &SignRequest::NilVote(claim.clone()))
        .unwrap();
    claim.vote_signature = signatures[0];
    claim.signature = signatures[1];
    let foreign = NilVote {
        data: nil(3),
        aggregation_bits: single_signer_bits(engine.active_validator_set().len(), 0),
        signature: signatures[0],
        attestations: vec![claim],
    };
    engine.observe_nil_votes_for_slashing(&foreign).unwrap();
    let seen = engine.doppelganger().unwrap();
    assert_eq!(seen.identity, *key(0).public_key_bytes());
    assert_eq!(
        engine.local_signing_policy(),
        LocalSigningPolicy {
            signing_paused: true,
            production_paused: true,
        }
    );
    // The pause is durable.
    let restarted = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert!(restarted.local_signing_policy().signing_paused);
    // The operator's resume clears the detection, so the next foreign
    // message pauses signing again.
    engine
        .set_local_signing_policy(LocalSigningPolicy::default())
        .unwrap();
    assert_eq!(engine.doppelganger(), None);
    engine.observe_nil_votes_for_slashing(&foreign).unwrap();
    assert!(engine.doppelganger().is_some());
    assert!(engine.local_signing_policy().signing_paused);
}

/// A key rotation seats the standby key in the local voter's seat; at that
/// validator-set transition the two swap, so signing follows the seat.
#[test]
fn a_rotation_swaps_the_standby_key_in_when_its_seat_takes_it() {
    let spec = spec();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_local_voter(key(0));
    engine.set_standby_voter(key(5));
    assert_eq!(
        engine.local_voter().unwrap().public_key_bytes(),
        key(0).public_key_bytes()
    );
    let mut rotated = spec.initial_validators;
    rotated[0].pubkey = *key(5).public_key_bytes();
    engine.set_active_validator_set(1, rotated).unwrap();
    assert_eq!(
        engine.local_voter().unwrap().public_key_bytes(),
        key(5).public_key_bytes()
    );
    assert_eq!(engine.local_voter().unwrap().validator_index(), 0);
    assert_eq!(
        engine.standby_voter.as_ref().unwrap().public_key_bytes(),
        key(0).public_key_bytes()
    );
}
