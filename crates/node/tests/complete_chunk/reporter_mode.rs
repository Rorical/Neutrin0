//! Reporter wiring through native evidence proving, gossip and recipient binding.

use super::{NativeConsensusBackend, engine};
use neutrin0_consensus_engine::{Engine, ProposerKey, RetentionPolicy};
use neutrin0_consensus_types::{
    BlockProof, BlockProofPublicInputs, FinalityVoteData, FinalityVotePhase, IndexedVote,
    SlashingEvidence,
    evidence::EvidenceReport,
    history_proof::{GuestPrograms, VkDigest},
    signed_artifacts::SignedArtifact,
};
use neutrin0_network::{Topic, service::NetworkCommand};
use neutrin0_node::ChainBackend;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_runtime_abi::BlockReceiptStatement;
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_storage::{Column, Database, MemoryDatabase};
use neutrin0_sync::{EvidenceProofAcceptance, SyncBackend};
use std::sync::{Arc, Mutex, atomic::AtomicUsize, mpsc};

struct UpgradedVerdictBackend {
    native: NativeConsensusBackend,
    expected_keys: Arc<Mutex<Vec<VkDigest>>>,
}

impl ProofSystem for UpgradedVerdictBackend {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        self.native.prove_block(witness, inputs, prover_address)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.native.verify_block(proof, inputs)
    }

    fn programs(&self) -> Option<GuestPrograms> {
        let mut programs = self.native.programs().unwrap();
        programs.execution.block = [99; 8];
        Some(programs)
    }

    fn prove_evidence_batch(
        &self,
        witnesses: &[neutrin0_prover_chunk::evidence::EvidenceWitness],
        execution: &neutrin0_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<Vec<neutrin0_consensus_types::evidence::EvidenceArtifact>, ProofError> {
        self.native.prove_evidence_batch(witnesses, execution)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        batch: &neutrin0_consensus_types::evidence::EvidenceBatch,
        program: &VkDigest,
    ) -> Result<(), ProofError> {
        self.native.verify_evidence(bytes, batch, program)
    }

    fn classify_block_rejection(
        &self,
        proof: &BlockProof,
        expected: &VkDigest,
    ) -> Result<Option<neutrin0_consensus_types::ProofRejectionReason>, ProofError> {
        self.expected_keys.lock().unwrap().push(*expected);
        if *expected != [1; 8] {
            return Ok(Some(
                neutrin0_consensus_types::ProofRejectionReason::PublicInputsMismatch,
            ));
        }
        let Ok(receipt) = borsh::from_slice::<BlockReceiptStatement>(&proof.proof_bytes) else {
            return Ok(Some(
                neutrin0_consensus_types::ProofRejectionReason::MalformedProof,
            ));
        };
        self.native.verify_block(&receipt, &proof.public_inputs)?;
        Ok(None)
    }
}

fn older_source_fixture() -> (Engine<MemoryDatabase>, BlockProof) {
    let (mut engine, template) = engine();
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let identities = engine
        .active_validator_set()
        .iter()
        .map(|validator| (validator.pubkey, validator.withdrawal_credentials))
        .collect::<Vec<_>>();
    engine.set_reporter_eligible(&identities).unwrap();
    // Importing the fixture block executed it: the engine holds the
    // authenticated final block's state.
    assert_eq!(engine.state().root(), engine.head_state_root());
    engine.flush_trie_to_store().unwrap();
    engine
        .finalize_chunk(
            0,
            &super::ready_prover(),
            &ProposerKey::from_ikm(&[42; 32], 0).unwrap(),
        )
        .unwrap();
    super::evidence_report_races::finalize_next_empty(&mut engine, &template);
    let proof = engine
        .store()
        .get_block_proof(&engine.head_hash())
        .unwrap()
        .unwrap();
    for _ in 0..9 {
        super::evidence_report_races::finalize_next_empty(&mut engine, &template);
    }
    (engine, proof)
}

#[test]
fn finalized_query_retains_all_accounts_and_old_opening_until_every_balance_is_zero() {
    use neutrin0_runtime_system::{Validator, encode_validator, validator_key};

    let old_account = super::support::credentials(8);
    let new_account = super::support::credentials(9);
    for (old_balance, new_balance) in [(100, 0), (0, 200), (0, 0)] {
        // The fixture genesis seats the validator at its old account; the
        // identity's retained new account carries whatever it moved there.
        let mut live = super::seeded_genesis_state();
        for (address, stake) in [(old_account, old_balance), (new_account, new_balance)] {
            live.insert(
                &validator_key(&address),
                encode_validator(&Validator { stake }),
            );
        }
        let (mut engine, _) = super::engine_with_live(&live);
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
        let pubkey = engine.active_validator_set()[0].pubkey;
        let identities = [(pubkey, old_account), (pubkey, new_account)];
        engine.set_reporter_eligible(&identities).unwrap();
        engine.flush_trie_to_store().unwrap();
        engine
            .finalize_chunk(
                0,
                &super::ready_prover(),
                &ProposerKey::from_ikm(&[42; 32], 0).unwrap(),
            )
            .unwrap();
        let opening = engine.store().reporter_opening(0).unwrap().unwrap();
        let header = engine.store().get_header_by_height(1).unwrap().unwrap();
        assert!(
            engine
                .store()
                .reporter_header(&header.hash())
                .unwrap()
                .is_some()
        );
        let backend = ChainBackend::new(engine, super::ready_prover());
        backend.set_block_executor(WasmExecutor::embedded().unwrap());
        // A second query must still inspect the zero old account alongside the
        // funded replacement: future deposits can make either one slashable.
        for _ in 0..2 {
            backend
                .initialize_reporter(neutrin0_primitives::runtime_account([77; 20]))
                .unwrap();
            backend.with_engine_mut_for_test(|engine| {
                let funded = old_balance != 0 || new_balance != 0;
                assert_eq!(
                    engine.store().reporter_tracked_validators().unwrap(),
                    if funded {
                        identities.to_vec()
                    } else {
                        Vec::new()
                    }
                );
                assert_eq!(
                    engine.store().reporter_opening(0).unwrap(),
                    funded.then(|| opening.clone())
                );
                assert_eq!(
                    engine.store().reporter_header(&header.hash()).unwrap(),
                    funded.then(|| header.clone())
                );
            });
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn older_valid_receipt_uses_retained_source_program_after_backend_upgrade() {
    let (mut engine, proof) = older_source_fixture();
    assert_eq!(
        engine
            .store()
            .historical_chunk(1)
            .unwrap()
            .unwrap()
            .block_guest_vk_digest,
        [1; 8]
    );
    // Source boundaries can be pruned; the independently authenticated historical
    // context keeps the receipt's own key even when the embedded prover changes.
    engine
        .store_mut()
        .db_mut()
        .delete(
            neutrin0_storage::Column::ConsensusBoundaries,
            &1_u64.to_be_bytes(),
        )
        .unwrap();
    engine
        .store_mut()
        .db_mut()
        .delete(
            neutrin0_storage::Column::HistoricalChunks,
            &1_u64.to_be_bytes(),
        )
        .unwrap();
    let expected_keys = Arc::new(Mutex::new(Vec::new()));
    let backend = ChainBackend::new(
        engine,
        UpgradedVerdictBackend {
            native: super::ready_prover(),
            expected_keys: Arc::clone(&expected_keys),
        },
    );
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::BlockProof(proof))
            .await,
        EvidenceProofAcceptance::Accepted
    );
    assert_eq!(*expected_keys.lock().unwrap(), vec![[1; 8]]);
    assert_eq!(backend.slashing_pool_len(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn old_rejected_receipt_arrival_and_restart_revisit_selectively_saved_acceptance() {
    let (mut engine, mut proof) = older_source_fixture();
    proof.proof_bytes = vec![0x99];
    let rejected = SignedArtifact::BlockProof(proof.clone());
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    // The same value the finalized certificate signed: its chunk and payment
    // selection (design 08), so only the proof acceptance is offending.
    let record = engine.store().historical_chunk(1).unwrap().unwrap();
    let data = FinalityVoteData {
        chunk_id: 1,
        round: 2,
        chunk_hash: record.chunk.hash(),
        selection: record.finality.proposal.selection(),
        phase: FinalityVotePhase::Precommit,
    };
    let vote = neutrin0_consensus_types::FinalityVote {
        proof_manifests: vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![rejected.id()],
        }],
        signature: signer.sign_finality_vote(domain, &data),
        aggregation_bits: neutrin0_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
        attestations: vec![signer.attest_vote(domain, data.clone(), vec![rejected.id()], None)],
        data,
    };
    engine.retain_signed_vote(&vote).unwrap();
    // Remove the ordinary discovery index: only the reporter's copy remains.
    for column in [Column::SignedArtifacts, Column::SignedArtifactIndex] {
        for (key, _) in engine.store().db().iter_column(column).unwrap() {
            engine.store_mut().db_mut().delete(column, &key).unwrap();
        }
    }
    let spec = engine.chain_spec().clone();
    let backend = ChainBackend::new(
        engine,
        UpgradedVerdictBackend {
            native: super::ready_prover(),
            expected_keys: Arc::new(Mutex::new(Vec::new())),
        },
    );
    assert_eq!(
        backend.ingest_signed_artifact(rejected.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    let offences = backend.drain_slashing_pool(8);
    assert!(
        matches!(offences.as_slice(), [SlashingEvidence::InvalidProofSigning { rejected_proof, .. }] if *rejected_proof == proof)
    );
    let database = backend.with_engine_mut_for_test(|engine| {
        // Startup must independently rediscover the old signed acceptance rather
        // than depending on a raw pool or ordinary source rows from the old run.
        for column in [
            Column::SignedArtifacts,
            Column::SignedArtifactIndex,
            Column::EvidenceProofs,
        ] {
            for (key, _) in engine.store().db().iter_column(column).unwrap() {
                engine.store_mut().db_mut().delete(column, &key).unwrap();
            }
        }
        engine.store().db().clone()
    });
    let reopened = Engine::open(spec, database).unwrap();
    assert_replay_dependencies(&reopened, &rejected);
    let replay_keys = Arc::new(Mutex::new(Vec::new()));
    let restarted = ChainBackend::new(
        reopened,
        UpgradedVerdictBackend {
            native: super::ready_prover(),
            expected_keys: Arc::clone(&replay_keys),
        },
    );
    restarted.resume_bft_sessions().await.unwrap();
    let replay_keys = replay_keys.lock().unwrap();
    assert!(!replay_keys.is_empty());
    assert!(replay_keys.iter().all(|key| *key == [1; 8]));
    drop(replay_keys);
    let replayed = restarted.drain_slashing_pool(8);
    assert!(
        matches!(replayed.as_slice(), [SlashingEvidence::InvalidProofSigning { rejected_proof, .. }] if *rejected_proof == proof),
        "restart must report only the malformed old receipt: {replayed:?}"
    );
}

fn assert_replay_dependencies(engine: &Engine<MemoryDatabase>, rejected: &SignedArtifact) {
    // A canonical receipt the Chunk Guest verified can support no offence, so
    // finalization copies none into reporter storage (design 18).
    assert!(
        engine
            .store()
            .reporter_sources_for_chunk(0)
            .unwrap()
            .iter()
            .all(|source| !matches!(source, SignedArtifact::BlockProof(_)))
    );
    assert_eq!(
        engine.store().signed_artifact(&rejected.id()).unwrap(),
        Some((1, rejected.clone()))
    );
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn reporter_worker_broadcasts_receipt_with_immutable_reward_recipient() {
    let (mut engine, _) = engine();
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let identities = engine
        .active_validator_set()
        .iter()
        .map(|validator| (validator.pubkey, validator.withdrawal_credentials))
        .collect::<Vec<_>>();
    engine.set_reporter_eligible(&identities).unwrap();
    // Importing the fixture block executed it: the engine holds the
    // authenticated final block's state for the runtime query.
    assert_eq!(engine.state().root(), engine.head_state_root());
    engine.flush_trie_to_store().unwrap();
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    engine
        .finalize_chunk(0, &prover, &ProposerKey::from_ikm(&[42; 32], 0).unwrap())
        .unwrap();
    let domain = engine.chain_spec().consensus_domain();
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let vote = |chunk_hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash,
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key.sign(&data.signing_message(domain)).to_bytes(),
            data,
        }
    };
    // An installed prover may already name a different block program. Evidence
    // must still use the chain's current admission key, while preserving its
    // source's historical key in the separately authenticated context.
    let backend = ChainBackend::new(
        engine,
        UpgradedVerdictBackend {
            native: prover,
            expected_keys: Arc::new(Mutex::new(Vec::new())),
        },
    );
    backend.set_block_executor(WasmExecutor::embedded().unwrap());
    backend
        .initialize_reporter(neutrin0_primitives::runtime_account([77; 20]))
        .unwrap();
    let (publisher, mut messages) = tokio::sync::mpsc::channel(16);
    backend.set_network_publisher(publisher);
    let _ = backend
        .ingest_slashing_evidence(SlashingEvidence::DoublePrecommit {
            validator_index: 0,
            vote_a: vote([1; 32]),
            vote_b: vote([2; 32]),
        })
        .await;
    let report = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish { topic, data } = messages.recv().await.unwrap() {
                assert_ne!(
                    topic,
                    Topic::SlashingEvidence,
                    "reporter publishes a reward-bound receipt before raw offence gossip"
                );
                if topic == Topic::EvidenceProofs {
                    break borsh::from_slice::<EvidenceReport>(&data).unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        report.artifact.statement.reporter,
        Some(neutrin0_primitives::runtime_account([77; 20]))
    );
    assert_eq!(report.artifact.statement.block_guest_vk_digest, [1; 8]);
    assert_eq!(
        report
            .artifact
            .statement
            .context
            .source_block_guest_vk_digest,
        [1; 8]
    );
    assert_eq!(
        report.artifact.statement.context.source_runtime_code_hash,
        neutrin0_runtime_host::embedded_runtime_code_hash()
    );
    assert_eq!(
        backend.ingest_evidence_proof(report.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    let mut stolen = report.clone();
    stolen.artifact.statement.reporter = Some(neutrin0_primitives::runtime_account([78; 20]));
    assert_eq!(
        backend.ingest_evidence_proof(stolen).await,
        EvidenceProofAcceptance::Rejected
    );
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_reports().unwrap(), vec![report]);
        assert_eq!(
            engine
                .store()
                .db()
                .iter_column(neutrin0_storage::Column::HistoryNodes)
                .unwrap(),
            [] as [(Vec<u8>, Vec<u8>); 0]
        );
    });
}
