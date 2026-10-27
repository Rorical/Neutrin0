//! Reporter ownership and long-lived forensic opening lifecycle.

use super::*;
use crate::ProposerKey;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{
    FinalityVote, FinalityVoteData, FinalityVotePhase, SlashingEvidence,
};
use neutrin0_storage::{Column, Database};

fn watched<DB: Database>(db: DB) -> Engine<DB>
where
    DB::Error: std::fmt::Debug,
{
    let mut engine = fixture(db, 0);
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let validators = engine.reporter_tracked_validators().unwrap();
    engine.set_reporter_eligible(&validators).unwrap();
    engine
}

fn signed_prevote(
    key: &ProposerKey,
    chain_spec: &ChainSpec,
    chunk: u64,
    target: u8,
) -> SignedArtifact {
    let data = FinalityVoteData {
        chunk_id: chunk,
        round: 7,
        phase: FinalityVotePhase::Prevote,
        chunk_hash: [target; 32],
        selection: crate::bft_loop::fixture_selection(),
    };
    SignedArtifact::Vote(FinalityVote {
        proof_manifests: Vec::new(),
        signature: key.sign_finality_vote(chain_spec.consensus_domain(), &data),
        attestations: vec![key.attest_vote(
            chain_spec.consensus_domain(),
            data.clone(),
            Vec::new(),
            None,
        )],
        aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
        data,
    })
}

fn retained_history_start(
    chain_spec: &ChainSpec,
    snapshot: bool,
    policy: RetentionPolicy,
) -> Engine<MemoryDatabase> {
    let source = fixture_with_spec(MemoryDatabase::new(), 9, chain_spec);
    if !snapshot {
        return source;
    }
    let chunk = source.store().get_chunk_proof(8).unwrap().unwrap();
    let statement = source.store().chunk_statement(8).unwrap().unwrap();
    let recent: Vec<_> = (1..9)
        .map(|chunk| source.store().historical_opening(chunk, 9).unwrap())
        .collect();
    let header = source.store().get_header_by_height(9).unwrap().unwrap();
    let state = source.state().detached().unwrap();
    let identity_sanctions = source.identity_sanctions.detached().unwrap();
    let consensus = source.store().get_consensus_state().unwrap().unwrap();
    let mut target = fixture_with_spec(MemoryDatabase::new(), 0, chain_spec);
    target.set_retention_policy(policy).unwrap();
    install_snapshot(&mut target, &state, &identity_sanctions);
    target
        .store_mut()
        .commit_bootstrap(
            Some((
                &crate::store::StoredChunkReceipt::new(chunk, &statement, 0),
                &statement,
            )),
            &ConsensusBoundary::genesis(chain_spec),
            &header,
            &consensus,
            &recent,
            &[],
        )
        .unwrap();
    target.publish_bootstrap_state(&consensus);
    target
}

fn publish_fixture_context(engine: &mut Engine<MemoryDatabase>, consensus: &ConsensusState) {
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::Finalized,
            crate::pointers::CONSENSUS_STATE,
            &borsh::to_vec(consensus).unwrap(),
        )
        .unwrap();
    engine.install_consensus_state(consensus);
}

#[test]
fn continuously_bonded_identity_keeps_old_openings_without_tree_or_block_bodies() {
    let mut engine = watched(MemoryDatabase::new());
    for _ in 0..40 {
        append(&mut engine);
    }
    engine.prune_finalized_history().unwrap();
    let opening = engine.store().historical_opening(0, 40).unwrap();
    assert_eq!(opening.record.chunk.chunk_id, 0);
    assert_eq!(opening.path.count, 40);
    assert!(opening.path.verify(
        commitment(&opening.record.evidence_context()),
        engine.canonical_boundary(40).unwrap().history_root
    ));
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap(),
        [] as [(Vec<u8>, Vec<u8>); 0]
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Blocks)
            .unwrap()
            .len(),
        8
    );
    assert!(
        engine
            .store()
            .db()
            .get(Column::Blocks, &opening.record.chunk.end_block_hash)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::ReporterHistory)
            .unwrap()
            .len(),
        40
    );
    let reopened = Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.store().historical_opening(0, 40).unwrap(), opening);
}

#[test]
fn exit_queue_identity_keeps_shared_material_until_finalized_economics_removes_last_owner() {
    let mut engine = watched(MemoryDatabase::new());
    append(&mut engine);
    let original = engine.reporter_tracked_validators().unwrap();
    // Removing the validator from the live committee is not an economic withdrawal.
    engine.set_active_validator_set(2, Vec::new()).unwrap();
    engine.set_reporter_eligible(&original).unwrap();
    assert!(engine.reporter_has_history().unwrap());
    assert!(engine.store().reporter_opening(0).unwrap().is_some());
    engine.set_reporter_eligible(&[]).unwrap();
    assert!(!engine.reporter_has_history().unwrap());
    assert_eq!(
        engine.store().reporter_tracked_validators().unwrap(),
        [] as [crate::ReporterIdentity; 0]
    );
}

#[test]
fn eligibility_cleanup_and_append_failure_publish_no_partial_reporter_state() {
    let mut engine = watched(FaultDb::default());
    append(&mut engine);
    let opening = engine.store().reporter_opening(0).unwrap().unwrap();
    engine.store_mut().db_mut().fail_batch = true;
    assert!(engine.set_reporter_eligible(&[]).is_err());
    assert_eq!(
        engine.store().reporter_opening(0).unwrap(),
        Some(opening.clone())
    );
    let record = engine.store().historical_chunk(0).unwrap().unwrap();
    let mut next = record;
    next.chunk.chunk_id = 1;
    let mut batch = Batch::new();
    engine
        .store()
        .append_history_batch(&mut batch, &next)
        .unwrap();
    assert!(engine.store_mut().db_mut().write_batch(batch).is_err());
    assert_eq!(engine.store().reporter_opening(0).unwrap(), Some(opening));
    assert!(engine.store().reporter_opening(1).unwrap().is_none());
}

#[test]
fn a_late_conflicting_signed_vote_is_discovered_after_the_normal_window_was_pruned() {
    let key = ProposerKey::from_ikm(&[41; 32], 0).unwrap();
    let mut chain_spec = spec();
    chain_spec.initial_validators[0].pubkey = *key.public_key_bytes();
    chain_spec.genesis_validator_set_root = commitment(&chain_spec.initial_validators);
    let mut engine = fixture_with_spec(MemoryDatabase::new(), 0, &chain_spec);
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let tracked = engine.reporter_tracked_validators().unwrap();
    engine.set_reporter_eligible(&tracked).unwrap();
    append(&mut engine);
    let first = signed_prevote(&key, &chain_spec, 0, 71);
    engine.retain_signed_artifact(&first, false).unwrap();
    assert_eq!(
        engine.observe_signed_artifact(&first).unwrap(),
        [] as [SlashingEvidence; 0]
    );
    for _ in 1..40 {
        append(&mut engine);
    }
    engine.prune_finalized_history().unwrap();
    engine.prune_availability_sources().unwrap();
    assert!(engine.accountability_validators(0).is_err());
    assert_eq!(
        engine
            .store()
            .signed_artifact(&first.id())
            .unwrap()
            .unwrap()
            .1,
        first
    );
    let second = signed_prevote(&key, &chain_spec, 0, 72);
    engine.retain_signed_artifact(&second, false).unwrap();
    let evidence = engine.observe_signed_artifact(&second).unwrap();
    assert!(
        evidence
            .iter()
            .any(|claim| matches!(claim, SlashingEvidence::DoublePrevote { .. }))
    );
    let mut restarted = Engine::open(chain_spec, engine.store().db().clone()).unwrap();
    assert!(
        restarted
            .replay_signed_artifacts()
            .unwrap()
            .iter()
            .any(|claim| matches!(claim, SlashingEvidence::DoublePrevote { .. }))
    );
}

#[test]
fn late_sources_promote_their_exact_old_context_after_pruned_or_snapshot_start() {
    let key = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let mut chain_spec = spec();
    chain_spec.initial_validators[0].pubkey = *key.public_key_bytes();
    chain_spec.genesis_validator_set_root = commitment(&chain_spec.initial_validators);
    for snapshot in [false, true] {
        let mut engine = retained_history_start(&chain_spec, snapshot, RetentionPolicy::Pruned);
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
        let original = engine.store().get_consensus_state().unwrap().unwrap();
        let mut rotated = original.clone();
        let mut successor = chain_spec.initial_validators[0].clone();
        successor.pubkey = [43; 48];
        successor.withdrawal_credentials = [44; 32];
        rotated.next_context.active_validators = vec![successor.clone()];
        publish_fixture_context(&mut engine, &rotated);
        engine
            .set_reporter_eligible(&[(successor.pubkey, successor.withdrawal_credentials)])
            .unwrap();
        assert!(engine.store().reporter_opening(8).unwrap().is_none());
        let mut signed_header = engine.store().get_header_by_height(9).unwrap().unwrap();
        signed_header.signature =
            key.sign_proposer_message(chain_spec.consensus_domain(), &signed_header.hash());
        if snapshot {
            engine.observe_header_for_slashing(&signed_header).unwrap();
        }
        let first = signed_prevote(&key, &chain_spec, 8, 71);
        engine.retain_signed_artifact(&first, false).unwrap();
        let old = &chain_spec.initial_validators[0];
        assert!(
            engine
                .store()
                .reporter_tracked_validators()
                .unwrap()
                .contains(&(old.pubkey, old.withdrawal_credentials))
        );
        assert_eq!(
            engine
                .store()
                .reporter_opening(8)
                .unwrap()
                .unwrap()
                .record
                .validators,
            chain_spec.initial_validators
        );
        if !snapshot {
            engine.observe_header_for_slashing(&signed_header).unwrap();
        }
        engine
            .set_reporter_eligible(&[(old.pubkey, old.withdrawal_credentials)])
            .unwrap();
        assert!(
            engine
                .store()
                .reporter_sources_for_chunk(8)
                .unwrap()
                .contains(&first)
        );
        publish_fixture_context(&mut engine, &original);
        for _ in 9..40 {
            append(&mut engine);
        }
        engine.prune_finalized_history().unwrap();
        engine.prune_availability_sources().unwrap();
        let mut restarted = Engine::open(chain_spec.clone(), engine.store().db().clone()).unwrap();
        assert_eq!(
            restarted
                .store()
                .reporter_header(&signed_header.hash())
                .unwrap(),
            Some(signed_header)
        );
        let second = signed_prevote(&key, &chain_spec, 8, 72);
        restarted.retain_signed_artifact(&second, false).unwrap();
        assert!(
            restarted
                .observe_signed_artifact(&second)
                .unwrap()
                .iter()
                .any(|claim| matches!(claim, SlashingEvidence::DoublePrevote { .. }))
        );
    }
}

#[test]
fn reporter_bootstrap_retains_observed_certificate_openings_before_any_late_source() {
    let chain_spec = spec();
    let mut engine = retained_history_start(&chain_spec, true, RetentionPolicy::Reporter);
    assert_eq!(
        engine.store().reporter_history_chunks().unwrap(),
        (1..9).collect::<Vec<_>>()
    );
    let opening = engine.store().reporter_opening(1).unwrap().unwrap();
    assert_eq!(opening.path.count, 9);
    let future = header(11, 11, engine.head_hash(), [0; 32]);
    engine
        .store_mut()
        .retain_reporter_header(10, &future, &chain_spec.initial_validators)
        .unwrap();
    assert!(
        engine
            .store()
            .reporter_header(&future.hash())
            .unwrap()
            .is_none()
    );
    for _ in 9..40 {
        append(&mut engine);
    }
    engine.prune_finalized_history().unwrap();
    assert!(
        engine
            .store()
            .db()
            .get(Column::HistoricalChunks, &1u64.to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap(),
        [] as [(Vec<u8>, Vec<u8>); 0]
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Blocks)
            .unwrap()
            .len(),
        8
    );
    let reopened = Engine::open(chain_spec, engine.store().db().clone()).unwrap();
    let retained = reopened.store().reporter_opening(1).unwrap().unwrap();
    assert_eq!(retained.record, opening.record);
    assert_eq!(retained.path.count, 40);
    assert!(retained.path.verify(
        commitment(&retained.record.evidence_context()),
        reopened.canonical_boundary(40).unwrap().history_root
    ));
}

#[test]
fn shared_historical_context_remains_for_another_slashable_validator() {
    let mut chain_spec = spec();
    let mut second = chain_spec.initial_validators[0].clone();
    second.pubkey = [44; 48];
    second.withdrawal_credentials = neutrin0_primitives::runtime_account([45; 20]);
    chain_spec.initial_validators.push(second.clone());
    chain_spec.genesis_validator_set_root = commitment(&chain_spec.initial_validators);
    let mut engine = fixture_with_spec(MemoryDatabase::new(), 0, &chain_spec);
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let tracked = engine.reporter_tracked_validators().unwrap();
    engine.set_reporter_eligible(&tracked).unwrap();
    append(&mut engine);
    let unique_header = header(1, 8, [0; 32], [0; 32]);
    let historical = engine.store().historical_chunk(0).unwrap().unwrap();
    engine
        .store_mut()
        .retain_reporter_header(0, &unique_header, &historical.validators)
        .unwrap();
    assert!(
        engine
            .store()
            .reporter_header(&unique_header.hash())
            .unwrap()
            .is_some()
    );
    engine
        .set_reporter_eligible(&[(second.pubkey, second.withdrawal_credentials)])
        .unwrap();
    assert!(
        engine
            .store()
            .reporter_header(&unique_header.hash())
            .unwrap()
            .is_none()
    );
    assert!(engine.store().reporter_opening(0).unwrap().is_some());
    assert_eq!(
        engine.store().reporter_tracked_validators().unwrap().len(),
        1
    );
    engine.set_reporter_eligible(&[]).unwrap();
    assert!(engine.store().reporter_opening(0).unwrap().is_none());
}

#[test]
fn finalized_exit_releases_raw_reports_before_releasing_their_context() {
    let mut engine = watched(MemoryDatabase::new());
    append(&mut engine);
    let first = neutrin0_consensus_types::IndexedVote {
        data: FinalityVoteData {
            chunk_id: 0,
            round: 3,
            phase: FinalityVotePhase::Prevote,
            chunk_hash: [81; 32],
            selection: crate::bft_loop::fixture_selection(),
        },
        signature: [0; 96],
    };
    let mut second = first.clone();
    second.data.chunk_hash = [82; 32];
    let evidence = SlashingEvidence::DoublePrevote {
        validator_index: 0,
        vote_a: first,
        vote_b: second,
    };
    let hash = engine.store_mut().put_slashing_evidence(&evidence).unwrap();
    let tracked = engine.reporter_tracked_validators().unwrap();
    assert_eq!(
        engine.set_reporter_eligible(&tracked).unwrap(),
        [] as [Hash; 0]
    );
    assert_eq!(engine.set_reporter_eligible(&[]).unwrap(), [hash]);
    assert_eq!(
        engine.store().iter_slashing_evidence().unwrap(),
        [] as [(Hash, SlashingEvidence); 0]
    );
    assert!(engine.store().reporter_opening(0).unwrap().is_none());
}

fn proof_source(engine: &Engine<MemoryDatabase>) -> SignedArtifact {
    let header = engine.store().get_header_by_height(1).unwrap().unwrap();
    SignedArtifact::BlockProof(neutrin0_consensus_types::BlockProof {
        prover_address: [0; 32],
        statement_key: [0; 32],
        height: header.height,
        block_hash: header.hash(),
        public_inputs: neutrin0_consensus_types::BlockProofPublicInputs {
            context: (neutrin0_prover_chunk::execution::runtime_context(
                &header,
                engine.trusted_genesis_boundary().unwrap(),
            ))
            .into(),
            chain_id: engine.chain_spec().chain_id,
            height: header.height,
            parent_block_hash: header.parent_hash,
            block_hash: header.hash(),
            state_root_before: engine.chain_spec().genesis_state_root,
            state_root_after: header.state_root,
            transactions_root: header.transactions_root,
            receipt_root: header.receipts_root,
            da_root: header.da_root,
            vm_code_hash: engine.chain_spec().runtime_code_hash,
            block_program: [3; 8],
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            proposer_address: engine.chain_spec().initial_validators[0].withdrawal_credentials,
            runtime_extra: header.runtime_extra,
            inputs_root: [0; 32],
        },
        proof_bytes: vec![5; 1024],
    })
}

fn proof_claim(engine: &Engine<MemoryDatabase>, proof: &SignedArtifact) -> SignedArtifact {
    let key = ProposerKey::from_ikm(&[9; 32], 0).unwrap();
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 3,
        phase: FinalityVotePhase::Precommit,
        chunk_hash: [84; 32],
        selection: crate::bft_loop::fixture_selection(),
    };
    SignedArtifact::Vote(FinalityVote {
        proof_manifests: vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![proof.id()],
        }],
        signature: key.sign_finality_vote(engine.consensus_domain(), &data),
        attestations: vec![key.attest_vote(
            engine.consensus_domain(),
            data.clone(),
            vec![proof.id()],
            None,
        )],
        aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
        data,
    })
}

fn replace_placeholder_receipt(engine: &mut Engine<MemoryDatabase>, source: &SignedArtifact) {
    if let SignedArtifact::BlockProof(proof) = source {
        // The generic pruning fixture stores an opaque receipt placeholder.
        engine
            .store_mut()
            .db_mut()
            .delete(Column::BlockProofs, &proof.block_hash)
            .unwrap();
        engine
            .store_mut()
            .put_block_proof(&proof.block_hash, proof)
            .unwrap();
    }
}

#[test]
fn finalized_genesis_receipt_uses_authenticated_source_program_after_backend_change() {
    let mut engine = watched(MemoryDatabase::new());
    append(&mut engine);
    let source = proof_source(&engine);
    replace_placeholder_receipt(&mut engine, &source);
    let chain_spec = engine.chain_spec().clone();
    let mut programs = domain(&chain_spec).programs.execution;
    programs.block = [99; 8];
    engine.set_programs(neutrin0_consensus_types::history_proof::GuestPrograms {
        execution: programs,
        chunk: domain(&chain_spec).chunk,
    });
    // Changing process configuration cannot rewrite the specification's genesis pin.
    assert_eq!(
        engine.programs_for_height(1).unwrap().execution.block,
        chain_spec.genesis_execution.block
    );
    engine
        .store_mut()
        .db_mut()
        .delete(Column::ConsensusBoundaries, &0u64.to_be_bytes())
        .unwrap();
    engine
        .store_mut()
        .db_mut()
        .delete(Column::HistoricalChunks, &0u64.to_be_bytes())
        .unwrap();
    assert!(engine.validate_signed_artifact(&source));
    engine.retain_signed_artifact(&source, false).unwrap();
    if let SignedArtifact::BlockProof(mut proof) = source {
        proof.public_inputs.vm_code_hash[0] ^= 1;
        assert!(!engine.validate_signed_artifact(&SignedArtifact::BlockProof(proof)));
    }
}

struct NoPayloadScan(MemoryDatabase);
impl Database for NoPayloadScan {
    type Error = core::convert::Infallible;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.0.read_handle()
    }
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.get(column, key)
    }
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.0.put(column, key, value)
    }
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        self.0.delete(column, key)
    }
    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.0.write_batch(batch)
    }
    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.0.write_batch_durable(batch)
    }
    fn iter_column(&self, column: Column) -> Result<neutrin0_storage::ColumnSnapshot, Self::Error> {
        assert!(
            !matches!(
                column,
                Column::ReporterSources | Column::ReporterHeaders | Column::ReporterHistory
            ),
            "identity lookup must not load the retained history"
        );
        self.0.iter_column(column)
    }
    fn iter_prefix(
        &self,
        column: Column,
        prefix: &[u8],
    ) -> Result<neutrin0_storage::ColumnSnapshot, Self::Error> {
        self.0.iter_prefix(column, prefix)
    }
}

#[test]
fn exact_proof_dependency_is_preserved_in_both_arrival_orders_and_its_indexes_are_reclaimed() {
    for proof_first in [true, false] {
        let mut engine = watched(MemoryDatabase::new());
        append(&mut engine);
        let source = proof_source(&engine);
        let vote = proof_claim(&engine, &source);
        replace_placeholder_receipt(&mut engine, &source);
        let order = if proof_first {
            [&source, &vote]
        } else {
            [&vote, &source]
        };
        for artifact in order {
            engine.store_mut().put_signed_artifact(0, artifact).unwrap();
        }
        assert!(
            engine
                .store()
                .reporter_sources_for_chunk(0)
                .unwrap()
                .contains(&source)
        );
        engine
            .store_mut()
            .db_mut()
            .delete(Column::SignedArtifacts, &source.id())
            .unwrap();
        if let SignedArtifact::BlockProof(proof) = &source {
            engine
                .store_mut()
                .db_mut()
                .delete(Column::BlockProofs, &proof.block_hash)
                .unwrap();
        }
        assert_eq!(
            engine.store().signed_artifact(&source.id()).unwrap(),
            Some((0, source.clone()))
        );
        let lookup = ChainStore::new(NoPayloadScan(engine.store().db().clone()));
        assert_eq!(
            lookup.signed_artifact(&source.id()).unwrap(),
            Some((0, source.clone()))
        );
        let retained_header = engine.store().get_header_by_height(1).unwrap().unwrap();
        assert_eq!(
            lookup.reporter_header(&retained_header.hash()).unwrap(),
            Some(retained_header)
        );
        assert_eq!(lookup.reporter_history_chunks().unwrap(), [0]);
        assert!(
            engine
                .store()
                .signed_artifact_inventory(0, None)
                .unwrap()
                .entries
                .iter()
                .any(|entry| entry.id == source.id())
        );
        let reopened =
            Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
        assert_eq!(
            reopened.store().signed_artifact(&source.id()).unwrap(),
            Some((0, source.clone()))
        );
        let mut corrupt = engine.store().db().clone();
        let mut key = vec![0];
        key.extend_from_slice(&source.id());
        corrupt
            .put(
                Column::ReporterIndex,
                &key,
                &borsh::to_vec(&999u64).unwrap(),
            )
            .unwrap();
        assert!(Engine::open(engine.chain_spec().clone(), corrupt).is_err());
        engine.set_reporter_eligible(&[]).unwrap();
        assert!(
            engine
                .store()
                .signed_artifact(&source.id())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            engine
                .store()
                .db()
                .iter_column(Column::ReporterIndex)
                .unwrap(),
            [] as [(Vec<u8>, Vec<u8>); 0]
        );
    }
}

#[test]
fn reporter_snapshot_jump_keeps_records_reports_the_gap_and_refreshes_dormant_paths() {
    let chain_spec = spec();
    let mut reporter = retained_history_start(&chain_spec, true, RetentionPolicy::Reporter);
    assert_eq!(
        reporter.store().reporter_history_chunks().unwrap(),
        (1..9).collect::<Vec<_>>()
    );
    // The reporter falls behind; an archive has finalized 40 chunks.
    let mut source = fixture_with_spec(MemoryDatabase::new(), 0, &chain_spec);
    source
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    for _ in 0..40 {
        append(&mut source);
    }
    let chunk = source.store().get_chunk_proof(39).unwrap().unwrap();
    let statement = source.store().chunk_statement(39).unwrap().unwrap();
    let recent: Vec<_> = (32..40)
        .map(|chunk| source.store().historical_opening(chunk, 40).unwrap())
        .collect();
    let header = source.store().get_header_by_height(40).unwrap().unwrap();
    let state = source.state().detached().unwrap();
    let identity_sanctions = source.identity_sanctions.detached().unwrap();
    let consensus = source.store().get_consensus_state().unwrap().unwrap();
    install_snapshot(&mut reporter, &state, &identity_sanctions);
    reporter
        .store_mut()
        .commit_bootstrap(
            Some((
                &crate::store::StoredChunkReceipt::new(chunk, &statement, 0),
                &statement,
            )),
            &ConsensusBoundary::genesis(&chain_spec),
            &header,
            &consensus,
            &recent,
            &[],
        )
        .unwrap();
    reporter.publish_bootstrap_state(&consensus);

    // Everything retained survives; what was jumped over is reported.
    assert_eq!(reporter.reporter_gaps().unwrap(), [(9, 32)]);
    assert!(reporter.store().reporter_record(1).unwrap().is_some());
    assert_eq!(
        reporter.reporter_dormant_chunks().unwrap(),
        (1..9).collect::<Vec<_>>()
    );
    assert!(reporter.store().reporter_opening(1).unwrap().is_none());
    assert_eq!(
        reporter
            .store()
            .reporter_opening(33)
            .unwrap()
            .unwrap()
            .path
            .count,
        40
    );
    let reopened = Engine::open(chain_spec, reporter.store().db().clone()).unwrap();
    assert_eq!(reopened.reporter_dormant_chunks().unwrap().len(), 8);

    // A peer's opening of the same leaf under the reporter's endpoint revives it.
    let opening = source.anchor_opening(1, 40).unwrap().unwrap();
    let mut forged = opening.clone();
    forged.path.siblings[0] = [0xEE; 32];
    assert!(!reporter.refresh_reporter_path(&forged).unwrap());
    assert!(reporter.refresh_reporter_path(&opening).unwrap());
    assert_eq!(
        reporter
            .store()
            .reporter_opening(1)
            .unwrap()
            .unwrap()
            .path
            .count,
        40
    );
    assert!(!reporter.reporter_dormant_chunks().unwrap().contains(&1));
}
