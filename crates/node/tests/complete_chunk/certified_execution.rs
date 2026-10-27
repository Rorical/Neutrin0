//! Native protocol checks; these transparent test receipts are not SP1 proofs.

use super::*;
use neutrin0_consensus_engine::ProductionConfig;
use neutrin0_consensus_types::{Body, history_proof::GuestPrograms};
use neutrin0_runtime_core::WitnessState;
use neutrin0_runtime_host::{WasmExecutor, decode_witness_bundle};

#[expect(
    clippy::redundant_pub_crate,
    reason = "Shared by sibling integration-test modules."
)]
pub(super) struct NativePipelineProofs;

#[derive(Clone)]
struct FailingDatabase {
    inner: MemoryDatabase,
    fail: bool,
}

impl neutrin0_storage::Database for FailingDatabase {
    type Error = std::io::Error;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.inner.read_handle()
    }
    fn get(
        &self,
        column: neutrin0_storage::Column,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.get(column, key).unwrap())
    }
    fn put(
        &mut self,
        column: neutrin0_storage::Column,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner.put(column, key, value).unwrap();
        Ok(())
    }
    fn delete(&mut self, column: neutrin0_storage::Column, key: &[u8]) -> Result<(), Self::Error> {
        self.inner.delete(column, key).unwrap();
        Ok(())
    }
    fn iter_column(
        &self,
        column: neutrin0_storage::Column,
    ) -> Result<neutrin0_storage::ColumnSnapshot, Self::Error> {
        Ok(self.inner.iter_column(column).unwrap())
    }
    fn write_batch(&mut self, batch: neutrin0_storage::Batch) -> Result<(), Self::Error> {
        if self.fail {
            return Err(std::io::Error::other("injected publication failure"));
        }
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }
    fn write_batch_durable(&mut self, batch: neutrin0_storage::Batch) -> Result<(), Self::Error> {
        self.write_batch(batch)
    }
}

impl ProofSystem for NativePipelineProofs {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn programs(&self) -> Option<GuestPrograms> {
        ready_prover().programs()
    }

    fn can_prove(&self, guests: &GuestPrograms) -> bool {
        let current = self.programs().unwrap();
        guests.chunk == current.chunk
            && guests.execution.fact == current.execution.fact
            && ((guests.execution.block == [1; 8] && guests.execution.evidence == [2; 8])
                || (guests.execution.block == [11; 8] && guests.execution.evidence == [12; 8]))
    }

    fn prove_block(
        &self,
        bytes: &[u8],
        _: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        let witness = decode_witness_bundle(bytes).map_err(|_| ProofError::MalformedProof)?;
        assert_eq!(
            witness.evidence_proofs,
            [] as [neutrin0_consensus_types::evidence::EvidenceArtifact; 0]
        );
        let mut state =
            WitnessState::new(&witness.state).map_err(|_| ProofError::InvalidWitness)?;
        Ok(BlockReceiptStatement {
            output: neutrin0_evm_runtime_core::execute_block(&witness.input, &mut state).output,
            prover_address,
        })
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        ready_prover().verify_block(proof, inputs)
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        Ok(proof.clone())
    }

    fn prove_consensus_chunk(
        &self,
        _: &[Self::BlockProof],
        _: &[Self::ChunkProof],
        witness: &ConsensusWitness,
        chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        validate_consensus(witness)
            .map(
                |statement| neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                    statement,
                    chunk_prover_address,
                },
            )
            .map_err(|_| ProofError::InvalidWitness)
    }

    fn chunk_prover_address(
        &self,
        proof: &Self::ChunkProof,
    ) -> Result<neutrin0_primitives::Hash, ProofError> {
        Ok(proof.chunk_prover_address)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &neutrin0_consensus_types::history_proof::ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        ready_prover().verify_consensus_chunk(proof, expected)
    }

    fn history_domain(
        &self,
        spec: &neutrin0_primitives::ChainSpec,
    ) -> Result<neutrin0_consensus_types::history_proof::ProofDomain, ProofError> {
        Ok(neutrin0_consensus_types::history_proof::ProofDomain {
            chain: neutrin0_consensus_types::history_proof::ChainBinding::new(spec),
            chunk: spec.genesis_chunk,
            programs: neutrin0_primitives::ProgramSet {
                runtime_code_hash: spec.runtime_code_hash,
                execution: spec.genesis_execution,
            },
        })
    }

    /// A native History receipt is the exact statement it proves.
    fn verify_history(
        &self,
        proof: &neutrin0_consensus_types::HistoryProof,
        chunk: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ProofError> {
        let receipt: Self::ChunkProof =
            borsh::from_slice(proof.receipt.as_slice()).map_err(|_| ProofError::BackendRejected)?;
        if *chunk != self.programs().ok_or(ProofError::Unsupported)?.chunk
            || receipt != proof.statement
        {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

fn certify(engine: &mut Engine<MemoryDatabase>, witness: &ConsensusWitness) {
    let mut prepared = engine
        .prepare_consensus_chunk(witness.context.chunk_id, &NativePipelineProofs)
        .unwrap();
    prepared.witness.finality_cert = witness.finality_cert.clone();
    assert!(
        engine
            .certify_execution_chunk(&prepared, &NativePipelineProofs, None)
            .unwrap()
    );
}

#[test]
fn certified_successor_executes_and_proves_before_finality_and_survives_restart() {
    let (mut engine, witness) = engine();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.set_local_voter(voter.clone());
    assert!(!engine.can_extend_execution());
    certify(&mut engine, &witness);
    let certified = *engine.certified_execution_boundary().unwrap();
    assert_eq!(certified.next_chunk_id, 1);
    assert_eq!(engine.finalized_next_chunk_id(), 0);
    assert!(engine.canonical_boundary(1).is_err());
    assert!(engine.store().get_finality_cert(0).unwrap().is_none());
    assert_eq!(engine.latest_history_proof().unwrap(), None);
    let executor = WasmExecutor::embedded().unwrap();
    let successor = engine
        .try_produce_block(
            2,
            ProductionConfig { proposer: &voter },
            Body::default(),
            &executor,
        )
        .unwrap()
        .unwrap()
        .block;
    assert_eq!(successor.header.height, 2);
    assert_eq!(successor.header.parent_hash, certified.block_hash);
    engine
        .prove_block(&successor.hash(), &NativePipelineProofs)
        .unwrap();
    assert_eq!(engine.finalized_next_chunk_id(), 0);
    assert!(!engine.can_extend_execution());
    assert!(
        engine
            .try_produce_block(
                3,
                ProductionConfig { proposer: &voter },
                Body::default(),
                &executor
            )
            .unwrap()
            .is_none()
    );

    let mut engine = Engine::open(witness.chain_spec, engine.store().db().clone()).unwrap();
    engine.set_local_voter(voter.clone());
    assert_eq!(engine.certified_execution_boundary(), Some(&certified));
    assert_eq!(engine.head_hash(), successor.hash());
    assert!(!engine.can_extend_execution());
    let prepared = engine
        .prepare_certified_execution(&NativePipelineProofs)
        .unwrap();
    let proof = NativePipelineProofs
        .prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            [0; 32],
        )
        .unwrap();
    engine
        .commit_bft_consensus_chunk(
            &prepared.witness,
            &proof,
            &NativePipelineProofs,
            Some(&executor),
        )
        .unwrap();
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    assert_eq!(engine.head_hash(), successor.hash());
    assert_eq!(engine.head_height(), 2);
    assert!(engine.certified_execution_boundary().is_none());
    assert_eq!(engine.canonical_boundary(1).unwrap(), certified);
    engine
        .finalize_chunk(1, &NativePipelineProofs, &voter)
        .unwrap();
    assert_eq!(engine.finalized_next_chunk_id(), 2);
    assert!(engine.can_extend_execution());
}

#[test]
fn a_snapshot_holding_the_certified_chunk_supersedes_the_dependency() {
    let (mut engine, witness) = engine();
    certify(&mut engine, &witness);
    // Another node finalized the same chunk. Peers that pruned the chunk's
    // proof leave its History proof and state as this node's only way on.
    let (mut source, _) = super::engine();
    certify(&mut source, &witness);
    let prepared = source
        .prepare_certified_execution(&NativePipelineProofs)
        .unwrap();
    let proof = NativePipelineProofs
        .prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            [0; 32],
        )
        .unwrap();
    source
        .commit_bft_consensus_chunk(&prepared.witness, &proof, &NativePipelineProofs, None)
        .unwrap();
    let history = source.latest_history_proof().unwrap().unwrap();
    let statement = history.statement.statement.clone();
    let consensus = source.store().get_consensus_state().unwrap().unwrap();
    let spec = witness.chain_spec.clone();
    // The dependency's chunk is the specification's first, so the History
    // record retained beside the snapshot shows which chunk finalized.
    engine
        .store_mut()
        .install_state_slice(
            &[
                statement.end.state_root,
                statement.end.identity_sanctions_root,
            ],
            source.state(),
            usize::MAX,
        )
        .unwrap();
    engine
        .install_bootstrap(
            neutrin0_proof_system::verify_history_proof(&NativePipelineProofs, &spec, history)
                .unwrap(),
            None,
            neutrin0_consensus_types::Checkpoint {
                chain: statement.chain,
                boundary: neutrin0_consensus_types::history_proof::ConsensusBoundary::first(&spec),
            },
            &source
                .store()
                .get_header_by_height(statement.end.height)
                .unwrap()
                .unwrap(),
            &consensus.next_context.active_validators,
            &consensus.frontier,
            &[source.store().historical_opening(0, 1).unwrap()],
            None,
        )
        .unwrap();
    assert!(engine.certified_execution_boundary().is_none());
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    let reopened = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert!(reopened.certified_execution_boundary().is_none());
    assert_eq!(reopened.finalized_next_chunk_id(), 1);
}

#[test]
fn invalid_certificate_cannot_advance_execution_or_persist_a_dependency() {
    let (mut engine, witness) = engine();
    let mut prepared = engine
        .prepare_consensus_chunk(0, &NativePipelineProofs)
        .unwrap();
    prepared.witness.finality_cert = witness.finality_cert.clone();
    prepared.witness.finality_cert.precommit.signature[0] ^= 1;
    assert!(
        engine
            .certify_execution_chunk(&prepared, &NativePipelineProofs, None)
            .is_err()
    );
    assert!(engine.certified_execution_boundary().is_none());
    assert!(!engine.can_extend_execution());
    let reopened = Engine::open(witness.chain_spec, engine.store().db().clone()).unwrap();
    assert!(reopened.certified_execution_boundary().is_none());
    assert_eq!(reopened.finalized_next_chunk_id(), 0);
}

#[test]
fn native_certification_rejects_unproven_fact_claims_and_corrupt_restart_data() {
    use neutrin0_prover_chunk::facts::{FactStatement, ProvenFact};
    use neutrin0_storage::{Column, Database};
    let (mut engine, witness) = engine();
    let mut prepared = engine
        .prepare_consensus_chunk(0, &NativePipelineProofs)
        .unwrap();
    prepared.witness.finality_cert = witness.finality_cert.clone();
    prepared.witness.facts.push(FactStatement {
        facts: vec![ProvenFact {
            id: [7; 32],
            valid: true,
        }],
    });
    assert!(
        engine
            .certify_execution_chunk(&prepared, &NativePipelineProofs, None)
            .is_err()
    );
    assert!(engine.certified_execution_boundary().is_none());
    certify(&mut engine, &witness);
    let mut database = engine.store().db().clone();
    database
        .put(Column::Meta, b"certified_execution", &[0; 8])
        .unwrap();
    assert!(Engine::open(witness.chain_spec, database).is_err());
}

#[test]
fn failed_durable_certification_or_finalization_keeps_disk_and_live_state_consistent() {
    let (engine, witness) = engine();
    let spec = witness.chain_spec.clone();
    let mut engine = Engine::open(
        spec.clone(),
        FailingDatabase {
            inner: engine.store().db().clone(),
            fail: false,
        },
    )
    .unwrap();
    engine.set_programs(NativePipelineProofs.programs().unwrap());
    let mut prepared = engine
        .prepare_consensus_chunk(0, &NativePipelineProofs)
        .unwrap();
    prepared.witness.finality_cert = witness.finality_cert;
    // Pinning the trust profile is independent of publishing progress.
    engine
        .set_history_domain(neutrin0_consensus_types::history_proof::ProofDomain {
            chain: engine.chain_binding(),
            chunk: engine.chain_spec().genesis_chunk,
            programs: engine.genesis_programs(),
        })
        .unwrap();
    engine.store_mut().db_mut().fail = true;
    assert!(
        engine
            .certify_execution_chunk(&prepared, &NativePipelineProofs, None)
            .is_err()
    );
    assert!(engine.certified_execution_boundary().is_none());
    assert_eq!(engine.finalized_next_chunk_id(), 0);
    assert!(
        Engine::open(spec.clone(), engine.store().db().clone())
            .unwrap()
            .certified_execution_boundary()
            .is_none()
    );
    engine.store_mut().db_mut().fail = false;
    engine
        .certify_execution_chunk(&prepared, &NativePipelineProofs, None)
        .unwrap();
    let boundary = *engine.certified_execution_boundary().unwrap();
    let proof = NativePipelineProofs
        .prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            [0; 32],
        )
        .unwrap();
    engine.store_mut().db_mut().fail = true;
    assert!(
        engine
            .commit_bft_consensus_chunk(&prepared.witness, &proof, &NativePipelineProofs, None)
            .is_err()
    );
    assert_eq!(engine.certified_execution_boundary(), Some(&boundary));
    assert_eq!(engine.finalized_next_chunk_id(), 0);
    let mut engine = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(engine.certified_execution_boundary(), Some(&boundary));
    engine.store_mut().db_mut().fail = false;
    engine
        .commit_bft_consensus_chunk(&prepared.witness, &proof, &NativePipelineProofs, None)
        .unwrap();
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    assert!(engine.certified_execution_boundary().is_none());
}

#[test]
fn certification_pins_its_value_and_rejects_a_conflicting_complete_certificate() {
    let (mut engine, first, second) = cached_candidate_fixture();
    let keys = [neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap()];
    let executor = WasmExecutor::embedded().unwrap();
    let mut prepared = engine
        .prepare_consensus_chunk_on_branch(0, first.end_block_hash, None, &NativePipelineProofs)
        .unwrap();
    prepared.witness.finality_cert =
        support::certificate_with_precommitters(&prepared.witness, &keys, &[0]);
    engine
        .certify_execution_chunk(&prepared, &NativePipelineProofs, Some(&executor))
        .unwrap();
    assert_eq!(engine.head_hash(), first.end_block_hash);
    assert_eq!(engine.fork_choice_head(), first.end_block_hash);
    let boundary = *engine.certified_execution_boundary().unwrap();
    let mut conflicting = engine
        .prepare_consensus_chunk_on_branch(0, second.end_block_hash, None, &NativePipelineProofs)
        .unwrap();
    conflicting.witness.finality_cert =
        support::certificate_with_precommitters(&conflicting.witness, &keys, &[0]);
    validate_consensus(&conflicting.witness).unwrap();
    assert!(
        engine
            .certify_execution_chunk(&conflicting, &NativePipelineProofs, Some(&executor))
            .is_err()
    );
    assert_eq!(engine.head_hash(), first.end_block_hash);
    assert_eq!(engine.certified_execution_boundary(), Some(&boundary));
    let restarted = Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    assert_eq!(restarted.fork_choice_head(), first.end_block_hash);
}

#[test]
#[allow(clippy::too_many_lines)] // Authenticate one committee/program handoff before predecessor proof finality.
fn certified_handoff_selects_successor_committee_and_programs_before_finality() {
    use neutrin0_consensus_types::{
        history_proof::{ProgramArtifacts, ProgramSet, ScheduledUpgrade},
        runtime::{
            BlsIdentity, CONSENSUS_CANDIDATES_KEY, ConsensusCandidate, ConsensusCandidates,
            UPGRADE_KEY,
        },
    };
    let (prototype, _) = engine();
    let programs = prototype.genesis_programs();
    let chunk_program = prototype.chain_spec().genesis_chunk;
    let old = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let next_key = neutrin0_crypto::bls::SecretKey::key_gen(&[43; 32], &[]).unwrap();
    let previous = prototype.active_validator_set()[0].clone();
    let next = ProgramSet {
        runtime_code_hash: programs.runtime_code_hash,
        execution: neutrin0_primitives::ExecutionPrograms {
            fact: programs.execution.fact,
            evidence: [12; 8],
            block: [11; 8],
        },
    };
    // Runtime genesis for the seated predecessor, then the candidate and
    // upgrade records this handoff reads: the predecessor retires and a
    // registered successor at another accountable account stands by.
    let successor_account = support::credentials(9);
    let mut live = support::evm_genesis_live(&support::evm_genesis_input(
        programs,
        30_000_000,
        0,
        std::slice::from_ref(&previous),
        1,
        neutrin0_primitives::RuntimeParams::default(),
    ));
    let mut candidates = ConsensusCandidates::default();
    candidates.upsert(ConsensusCandidate {
        address: previous.withdrawal_credentials,
        stake: 0,
        identity: None,
    });
    candidates.upsert(ConsensusCandidate {
        address: successor_account,
        stake: 100,
        identity: Some(BlsIdentity {
            pubkey: next_key.public_key().to_bytes(),
            pop_signature: next_key.prove_registration(&successor_account).to_bytes(),
        }),
    });
    live.insert(
        CONSENSUS_CANDIDATES_KEY,
        borsh::to_vec(&candidates).unwrap(),
    );
    live.insert(
        UPGRADE_KEY,
        borsh::to_vec(&ScheduledUpgrade {
            activate_at_chunk: 2,
            programs: next,
            artifacts: ProgramArtifacts::default(),
            available: true,
        })
        .unwrap(),
    );
    let (witness, input, _) = support::fixture_with_execution_configuration(
        programs,
        chunk_program,
        std::slice::from_ref(&previous),
        std::slice::from_ref(&old),
        Vec::new(),
        30_000_000,
        30_000_000,
        &live,
        neutrin0_evm_runtime_core::execute_block,
        0,
        |spec| {
            spec.consensus.epoch_length_in_chunks = 1;
            spec.consensus.activation_delay_epochs = 1;
            spec.consensus.exit_delay_epochs = 1;
        },
    );
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(NativePipelineProofs.programs().unwrap());
    engine.install_genesis_state(live.trie().clone()).unwrap();
    engine.flush_trie_to_store().unwrap();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: block.header.clone(),
                body: support::executed_body(&live, &input),
            },
            &super::native_executor::NativeExecutor,
        )
        .unwrap();
    engine
        .store_mut()
        .put_proven_block(
            &hash,
            &BlockProof {
                prover_address: block.public_inputs.proposer_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&block.statement()),
                height: 1,
                block_hash: hash,
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&block.statement()).unwrap(),
            },
        )
        .unwrap();
    let executor = WasmExecutor::embedded().unwrap();
    let old_voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine
        .finalize_chunk(0, &NativePipelineProofs, &old_voter)
        .unwrap();
    let block = engine
        .try_produce_block(
            2,
            ProductionConfig {
                proposer: &old_voter,
            },
            Body::default(),
            &executor,
        )
        .unwrap()
        .unwrap()
        .block;
    engine
        .prove_block(&block.hash(), &NativePipelineProofs)
        .unwrap();
    let mut pending = engine
        .prepare_consensus_chunk(1, &NativePipelineProofs)
        .unwrap();
    // Design 08: chunk 1's certificate ratifies chunk 0's finalized proof.
    let chunk = neutrin0_prover_chunk::consensus::as_chunk(&pending.candidate.execution.chunk);
    pending.witness.ratified = engine
        .ratification_selection(&chunk)
        .unwrap()
        .unwrap()
        .iter()
        .map(
            |entry| neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                statement: engine
                    .store()
                    .chunk_statement(entry.chunk_id)
                    .unwrap()
                    .unwrap(),
                chunk_prover_address: entry.prover_address,
            },
        )
        .collect();
    pending.witness.finality_cert = support::certificate_with_precommitters(
        &pending.witness,
        &[old.clone(), next_key.clone()],
        &[0],
    );
    // The newly registered seat is still inactive in this incoming committee.
    // Only its active predecessor signs either phase of this certificate.
    let certificate = &mut pending.witness.finality_cert;
    let domain = pending.witness.chain_spec.consensus_domain();
    certificate.prevote.aggregation_bits =
        neutrin0_primitives::BitVec::from_bytes(2, vec![1]).unwrap();
    certificate.prevote.signature = old
        .sign(&certificate.prevote_vote().data.signing_message(domain))
        .to_bytes();
    certificate
        .prevote_attestations
        .retain(|claim| claim.validator_index == 0);
    let locking = neutrin0_consensus_types::QuorumCertificate {
        data: certificate.prevote_vote().data,
        aggregate: certificate.prevote.clone(),
    };
    for claim in &mut certificate.precommit_attestations {
        claim.unlock_quorum = Some(locking.clone());
        claim.signature = old.sign(&claim.signing_message(domain)).to_bytes();
    }
    assert!(
        engine
            .certify_execution_chunk(&pending, &NativePipelineProofs, None)
            .unwrap()
    );
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    assert_eq!(engine.active_validator_set().len(), 2);
    assert_eq!(engine.active_validator_set()[0].pubkey, previous.pubkey);
    assert_eq!(engine.active_validator_set()[1].effective_stake, 0);
    assert_eq!(engine.programs_for_height(2).unwrap(), programs);
    assert_eq!(engine.programs_for_height(3).unwrap(), next);
    let (validators, seed) = engine.validator_context_for_height(3).unwrap();
    assert_eq!(validators.len(), 1);
    assert_eq!(validators[0].pubkey, next_key.public_key().to_bytes());
    assert_eq!(seed, engine.certified_execution_boundary().unwrap().seed);
    let executor = WasmExecutor::embedded().unwrap();
    let old_voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    assert!(
        engine
            .try_produce_block(
                3,
                ProductionConfig {
                    proposer: &old_voter
                },
                Body::default(),
                &executor
            )
            .unwrap()
            .is_none()
    );
    let next_voter = ProposerKey::from_ikm(&[43; 32], 99).unwrap();
    let successor = engine
        .try_produce_block(
            3,
            ProductionConfig {
                proposer: &next_voter,
            },
            Body::default(),
            &executor,
        )
        .unwrap()
        .unwrap()
        .block;
    assert_eq!(successor.header.proposer_index, 0);
    let proved = engine
        .prove_block(&successor.hash(), &NativePipelineProofs)
        .unwrap();
    assert_eq!(proved.public_inputs.block_program, next.execution.block);
    assert_eq!(proved.public_inputs.proposer_address, successor_account);
    let mut engine = Engine::open(witness.chain_spec, engine.store().db().clone()).unwrap();
    let prepared = engine
        .prepare_certified_execution(&NativePipelineProofs)
        .unwrap();
    let proof = NativePipelineProofs
        .prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            [0; 32],
        )
        .unwrap();
    engine
        .commit_bft_consensus_chunk(
            &prepared.witness,
            &proof,
            &NativePipelineProofs,
            Some(&executor),
        )
        .unwrap();
    assert_eq!(engine.active_validator_set(), validators);
    assert_eq!(engine.head_hash(), successor.hash());
    let successor = engine
        .prepare_consensus_chunk(2, &NativePipelineProofs)
        .unwrap();
    assert_eq!(successor.witness.context.programs, next);
}

#[tokio::test]
async fn peer_certificate_is_available_before_proof_and_only_authorizes_execution() {
    let (mut source, witness) = engine();
    let (destination, _) = engine();
    certify(&mut source, &witness);
    let executor = WasmExecutor::embedded().unwrap();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    source
        .try_produce_block(
            2,
            ProductionConfig { proposer: &voter },
            Body::default(),
            &executor,
        )
        .unwrap()
        .unwrap();
    let source = Engine::open(witness.chain_spec.clone(), source.store().db().clone()).unwrap();
    let source = ChainBackend::new(source, NativePipelineProofs);
    let destination = ChainBackend::new(destination, NativePipelineProofs);
    // Suppress immediate local proving; the imported certificate must remain
    // observable independently of the complete proof's eventual result.
    destination.set_proving_policy(neutrin0_node::config::ProvingPolicy {
        chunk_fallback_secs: u64::MAX,
        ..Default::default()
    });
    let candidate = source.bft_candidate(0, None).await.unwrap().candidate;
    assert_eq!(candidate.chunk.hash(), witness.finality_cert.chunk_hash);
    let response = source.finality_certs_by_chunk(&[0]).await.unwrap();
    assert_eq!(response.certs, vec![witness.finality_cert]);
    destination
        .verify_and_import_execution_certificate(response.certs[0].clone())
        .await
        .unwrap();
    assert_eq!(
        destination.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    destination.with_engine_mut_for_test(|engine| {
        assert!(engine.can_extend_execution());
        assert_eq!(engine.certified_execution_boundary().unwrap().height, 1);
    });
}

#[test]
fn certified_successor_forks_remain_eligible_and_finalization_preserves_the_selected_head() {
    let (mut first, witness) = engine();
    certify(&mut first, &witness);
    let mut second = Engine::open(witness.chain_spec.clone(), first.store().db().clone()).unwrap();
    let executor = WasmExecutor::embedded().unwrap();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let left = first
        .try_produce_block(
            2,
            ProductionConfig { proposer: &voter },
            Body::default(),
            &executor,
        )
        .unwrap()
        .unwrap()
        .block;
    let right = second
        .try_produce_block(
            3,
            ProductionConfig { proposer: &voter },
            Body::default(),
            &executor,
        )
        .unwrap()
        .unwrap()
        .block;
    assert_ne!(left.hash(), right.hash());
    first.import_block(&right, &executor).unwrap();
    second.import_block(&left, &executor).unwrap();
    let selected = first.fork_choice_head();
    assert!(selected == left.hash() || selected == right.hash());
    assert_eq!(selected, second.fork_choice_head());
    first
        .materialise_to_fork_choice_head(Some(&executor))
        .unwrap();
    assert_eq!(first.head_hash(), selected);
    let prepared = first
        .prepare_certified_execution(&NativePipelineProofs)
        .unwrap();
    let proof = NativePipelineProofs
        .prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            [0; 32],
        )
        .unwrap();
    first
        .commit_bft_consensus_chunk(
            &prepared.witness,
            &proof,
            &NativePipelineProofs,
            Some(&executor),
        )
        .unwrap();
    assert_eq!(first.head_hash(), selected);
    assert_eq!(first.finalized_next_chunk_id(), 1);
    let reopened = Engine::open(witness.chain_spec, first.store().db().clone()).unwrap();
    assert_eq!(reopened.head_hash(), selected);
    assert_eq!(reopened.fork_choice_head(), selected);
}

#[test]
fn independently_encoded_peer_quorum_finalizes_the_same_certified_boundary() {
    let keys: Vec<_> = (42..46)
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let (mut witness, input, _, post) = support::fixture_with_validator_keys(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
        &keys,
    );
    let genesis = support::spec_genesis_live(&witness);
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(NativePipelineProofs.programs().unwrap());
    engine
        .install_genesis_state(genesis.trie().clone())
        .unwrap();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: block.header.clone(),
                body: support::executed_body(&genesis, &input),
            },
            &super::native_executor::NativeExecutor,
        )
        .unwrap();
    assert_eq!(engine.state().root(), post.trie().root());
    engine.flush_trie_to_store().unwrap();
    engine
        .store_mut()
        .put_proven_block(
            &hash,
            &BlockProof {
                prover_address: block.public_inputs.proposer_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&block.statement()),
                height: 1,
                block_hash: hash,
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&block.statement()).unwrap(),
            },
        )
        .unwrap();
    witness.finality_cert = support::certificate_with_precommitters(&witness, &keys, &[0, 1, 2]);
    certify(&mut engine, &witness);
    let boundary = *engine.certified_execution_boundary().unwrap();
    let mut peer = engine
        .prepare_certified_execution(&NativePipelineProofs)
        .unwrap();
    peer.witness.finality_cert =
        support::certificate_with_precommitters(&peer.witness, &keys, &[0, 1, 3]);
    assert_ne!(peer.witness.finality_cert, witness.finality_cert);
    let proof = NativePipelineProofs
        .prove_consensus_chunk(&peer.proofs, &peer.ratified, &peer.witness, [0; 32])
        .unwrap();
    // Peer imports authenticate the complete statement independently. Exact local
    // job fencing must not mistake an equivalent quorum encoding for a fork.
    let wire = neutrin0_consensus_types::ChunkProof {
        finality_cert: peer.witness.finality_cert,
        chunk_id: proof.statement.chunk.chunk_id,
        chunk_hash: neutrin0_prover_chunk::consensus::as_chunk(&proof.statement.chunk).hash(),
        public_inputs: proof.statement.chunk.clone(),
        prover_address: proof.chunk_prover_address,
        proof_bytes: borsh::to_vec(&proof).unwrap(),
    };
    engine
        .import_chunk_proof(&wire, &NativePipelineProofs)
        .unwrap();
    assert_eq!(engine.canonical_boundary(1).unwrap(), boundary);
    assert!(engine.certified_execution_boundary().is_none());
    assert_eq!(engine.finalized_next_chunk_id(), 1);
}
