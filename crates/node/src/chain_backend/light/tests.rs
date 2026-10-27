use super::*;
use neutrin0_consensus_types::history_proof::{
    ChainBinding, ChunkReceiptStatement, ConsensusBoundary, ConsensusStatement, ExecutionPrograms,
    ProgramSet, ProofDomain,
};
use neutrin0_primitives::BoundedBytes;
use neutrin0_storage::{Batch, Column};

const CHUNK: [u32; 8] = [4; 8];

fn programs() -> ProgramSet {
    ProgramSet {
        runtime_code_hash: [2; 32],
        execution: ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
    }
}

fn inputs(chunk_id: u64) -> neutrin0_consensus_types::ChunkProofPublicInputs {
    neutrin0_consensus_types::ChunkProofPublicInputs {
        chunk_id,
        start_height: chunk_id + 1,
        end_height: chunk_id + 1,
        start_state_root: [2; 32],
        end_state_root: [2; 32],
        start_block_hash: [1; 32],
        end_block_hash: [1; 32],
        block_hash_root: [0; 32],
        block_proof_root: [0; 32],
        vrf_proof_root: [0; 32],
        active_validator_set_root: [3; 32],
        next_validator_set_root: [3; 32],
        next_identity_sanctions_root: [0; 32],
        da_root: [0; 32],
    }
}

/// The History proof of chunk `end - 1`, receipt bound to its statement.
fn signed(chain: ChainBinding, start: &ConsensusBoundary, end: &ConsensusBoundary) -> HistoryProof {
    let statement = ChunkReceiptStatement {
        statement: ConsensusStatement {
            chain,
            start: *start,
            end: *end,
            chunk: inputs(start.next_chunk_id),
            finality_cert_hash: [0; 32],
        },
        chunk_prover_address: [0; 32],
    };
    HistoryProof {
        receipt: BoundedBytes::new(statement.statement_key().to_vec()).unwrap(),
        statement,
    }
}

fn artifact() -> HistoryProof {
    let chain = ChainBinding {
        chain_spec_hash: [1; 32],
    };
    let start = ConsensusBoundary {
        identity_sanctions_root: [0; 32],

        next_chunk_id: 0,
        height: 0,
        block_hash: [1; 32],
        state_root: [2; 32],
        slot: 0,
        validators_root: [3; 32],
        seed: [4; 32],
        history_root: [5; 32],
        programs: programs(),
        participation: [6; 32],
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        fork: None,
    };
    let end = ConsensusBoundary {
        next_chunk_id: 1,
        height: 1,
        slot: 1,
        ..start
    };
    signed(chain, &start, &end)
}

fn start_checkpoint(proof: &HistoryProof) -> Checkpoint {
    Checkpoint {
        chain: *proof.chain(),
        boundary: proof.statement.statement.start,
    }
}

#[test]
fn persisted_pairs_reject_missing_or_mismatched_receipts() {
    let proof = artifact();
    let stored = StoredLight {
        snapshot: LightClientSnapshot {
            checkpoint: proof.end_checkpoint(),
            anchor_expires_at: 200,
        },
        trust_origin: start_checkpoint(&proof),
        trusted_at: 100,
        proof_key: Some(proof.statement.statement_key()),
    };
    let bytes = borsh::to_vec(&proof).unwrap();
    assert_eq!(
        stored.decode_latest(Some(&bytes), 200).unwrap(),
        Some(proof.clone())
    );
    assert!(stored.decode_latest(None, 200).is_err());
    let mut wrong = proof;
    wrong.statement.statement.end.state_root = [99; 32];
    assert!(
        stored
            .decode_latest(Some(&borsh::to_vec(&wrong).unwrap()), 200)
            .is_err()
    );
    let encoded = borsh::to_vec(&stored).unwrap();
    assert!(encoded.len() <= MAX_STATE_BYTES);
    assert!(StoredLight::decode(&encoded, &stored.trust_origin, 101).is_err());
}

#[test]
fn initial_anchor_cannot_gain_an_endpoint_or_expiry_without_a_receipt() {
    let proof = artifact();
    let mut stored = StoredLight {
        snapshot: LightClientSnapshot {
            checkpoint: start_checkpoint(&proof),
            anchor_expires_at: 200,
        },
        trust_origin: start_checkpoint(&proof),
        trusted_at: 100,
        proof_key: None,
    };
    assert!(stored.decode_latest(None, 200).unwrap().is_none());
    stored.snapshot.anchor_expires_at = 201;
    assert!(stored.decode_latest(None, 200).is_err());
    stored.snapshot.anchor_expires_at = 200;
    stored.snapshot.checkpoint = proof.end_checkpoint();
    assert!(stored.decode_latest(None, 200).is_err());
}

// This verifier exists only in this unit-test module. It authenticates exact
// statement bytes so backend routing/persistence can be tested without SP1.
struct FixtureVerifier;
impl ProofSystem for FixtureVerifier {
    type BlockProof = Vec<u8>;
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        _: &[u8],
        _: &neutrin0_consensus_types::BlockProofPublicInputs,
        _: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, neutrin0_proof_system::ProofError> {
        Err(neutrin0_proof_system::ProofError::Unsupported)
    }

    fn verify_block(
        &self,
        _: &Self::BlockProof,
        _: &neutrin0_consensus_types::BlockProofPublicInputs,
    ) -> Result<(), neutrin0_proof_system::ProofError> {
        Err(neutrin0_proof_system::ProofError::Unsupported)
    }

    fn history_domain(
        &self,
        spec: &neutrin0_primitives::ChainSpec,
    ) -> Result<ProofDomain, neutrin0_proof_system::ProofError> {
        Ok(ProofDomain {
            chain: ChainBinding::new(spec),
            chunk: spec.genesis_chunk,
            programs: programs(),
        })
    }

    fn verify_history(
        &self,
        proof: &HistoryProof,
        chunk: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), neutrin0_proof_system::ProofError> {
        if *chunk == CHUNK && proof.receipt.as_slice() == proof.statement.statement_key() {
            Ok(())
        } else {
            Err(neutrin0_proof_system::ProofError::PublicInputMismatch)
        }
    }
}

#[derive(Clone, Default)]
struct FaultDatabase {
    inner: neutrin0_storage::MemoryDatabase,
    fail_next_batch: bool,
    successful_batches: usize,
    last_batch: Vec<neutrin0_storage::BatchOp>,
}
impl Database for FaultDatabase {
    type Error = &'static str;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.inner.read_handle()
    }
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.get(column, key).unwrap())
    }
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.inner.put(column, key, value).unwrap();
        Ok(())
    }
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        self.inner.delete(column, key).unwrap();
        Ok(())
    }
    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        if core::mem::take(&mut self.fail_next_batch) {
            return Err("injected atomic batch failure");
        }
        self.last_batch = batch.operations().to_vec();
        self.inner.write_batch(batch).unwrap();
        self.successful_batches += 1;
        Ok(())
    }
    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.write_batch(batch)
    }

    fn iter_column(&self, column: Column) -> Result<neutrin0_storage::ColumnSnapshot, Self::Error> {
        Ok(self.inner.iter_column(column).unwrap())
    }
}
type TestBackend = ChainBackend<FaultDatabase, FixtureVerifier>;

fn chain_spec(now: u64) -> neutrin0_primitives::ChainSpec {
    use neutrin0_primitives::{
        ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo, RuntimeParams,
        Validator,
    };
    let validators = vec![Validator {
        pubkey: [1; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([2; 20]),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }];
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"light-backend-test".to_vec()).unwrap(),
        chain_id: 9,
        genesis_time: now - 20,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        // The genesis boundary names the spec's programs, which the fixture
        // verifier's domain must reproduce exactly.
        runtime_code_hash: programs().runtime_code_hash,
        genesis_chunk: CHUNK,
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [2; 32],
        genesis_state_root: [3; 32],
        genesis_block_hash: [4; 32],
        genesis_validator_set_root: neutrin0_primitives::validators_root(&validators),
        consensus: ConsensusParams {
            slot_duration_secs: 1,
            chunk_size: 1,
            ..ConsensusParams::default()
        },
        proof: ProofParams::default(),
        light_client: LightClientParams {
            weak_subjectivity_period_secs: 600,
            stale_threshold_secs: 120,
        },
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(vec![]).unwrap(),
    }
}

fn backend(spec: &neutrin0_primitives::ChainSpec, trusted_at: u64) -> (TestBackend, Checkpoint) {
    let domain = FixtureVerifier.history_domain(spec).unwrap();
    let origin = Checkpoint {
        chain: domain.chain,
        boundary: domain.genesis_boundary(spec),
    };
    let engine =
        neutrin0_consensus_engine::Engine::genesis(spec.clone(), FaultDatabase::default()).unwrap();
    let backend = ChainBackend::new(engine, FixtureVerifier);
    backend.initialize_light(origin, trusted_at, 30).unwrap();
    (backend, origin)
}

/// A genesis-trusting client's jump to the endpoint at `count` chunks.
fn jump_to(origin: &Checkpoint, count: u64, slot: u64) -> HistoryProof {
    let byte = u8::try_from(count).unwrap();
    signed(
        origin.chain,
        &ConsensusBoundary {
            next_chunk_id: count - 1,
            height: count - 1,
            ..origin.boundary
        },
        &ConsensusBoundary {
            next_chunk_id: count,
            height: count,
            slot,
            block_hash: [byte; 32],
            state_root: [byte + 1; 32],
            history_root: [byte + 2; 32],
            ..origin.boundary
        },
    )
}
fn jump(origin: &Checkpoint) -> HistoryProof {
    jump_to(origin, 3, 20)
}
/// The endpoint at `count` chunks whose History opens the leaf at
/// `start`'s count as having started from `start`, with that opening.
fn opened_jump(
    origin: &Checkpoint,
    count: u64,
    slot: u64,
    start: &ConsensusBoundary,
) -> (HistoryProof, AnchorOpening) {
    use neutrin0_consensus_types::evidence::{EvidenceContext, commitment};
    use neutrin0_consensus_types::history::{HistoryFrontier, HistoryPath};
    let index = usize::try_from(start.next_chunk_id).unwrap();
    let contexts: Vec<_> = (0..count)
        .map(|chunk_id| EvidenceContext {
            chunk_id,
            chunk_hash: [7; 32],
            end_height: chunk_id + 1,
            validators_root: origin.boundary.validators_root,
            seed: origin.boundary.seed,
            source_block_guest_vk_digest: [3; 8],
            source_runtime_code_hash: [2; 32],
            start_boundary: if chunk_id == start.next_chunk_id {
                start.commitment()
            } else {
                [5; 32]
            },
        })
        .collect();
    let leaves: Vec<_> = contexts.iter().map(commitment).collect();
    let jumped = jump_to(origin, count, slot).statement.statement;
    let end = ConsensusBoundary {
        history_root: HistoryFrontier::from_leaves(&leaves)
            .unwrap()
            .root()
            .unwrap(),
        ..jumped.end
    };
    let opening = AnchorOpening {
        context: contexts[index],
        path: HistoryPath::build(&leaves, index).unwrap(),
    };
    (signed(jumped.chain, &jumped.start, &end), opening)
}
fn snapshot(backend: &TestBackend) -> LightClientSnapshot {
    backend
        .light
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .client
        .snapshot()
}
fn database(backend: &TestBackend) -> FaultDatabase {
    backend.with_engine(|engine| engine.store().db().clone())
}

/// Trust configured after the anchor's block was produced expires from the
/// block's time, and a restart under the same configuration restores it.
#[test]
fn late_trust_restarts_with_the_anchor_expiry() {
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time + 50);
    let expiry = spec.genesis_time + spec.light_client.weak_subjectivity_period_secs;
    assert_eq!(snapshot(&backend).anchor_expires_at, expiry);
    let engine = neutrin0_consensus_engine::Engine::open(spec.clone(), database(&backend)).unwrap();
    let restarted = ChainBackend::new(engine, FixtureVerifier);
    restarted
        .initialize_light(origin, spec.genesis_time + 50, 30)
        .unwrap();
    assert_eq!(snapshot(&restarted).anchor_expires_at, expiry);
}

#[test]
fn light_health_reports_current_and_expired_anchors_without_renewing_trust() {
    let now = timestamp().unwrap();
    let spec = chain_spec(now);
    let (current, current_origin) = backend(&spec, spec.genesis_time);
    let before = snapshot(&current);
    assert_eq!(
        current.light_health(),
        Some(LightHealth {
            checkpoint: current_origin,
            expired: false,
            halted: false,
        })
    );
    assert_eq!(snapshot(&current), before);

    let expired_spec = chain_spec(now - spec.light_client.weak_subjectivity_period_secs - 20);
    let (expired, expired_origin) = backend(&expired_spec, expired_spec.genesis_time);
    let before = snapshot(&expired);
    assert!(before.anchor_expires_at < now);
    assert_eq!(
        expired.light_health(),
        Some(LightHealth {
            checkpoint: expired_origin,
            expired: true,
            halted: false,
        })
    );
    assert_eq!(snapshot(&expired), before);

    let engine =
        neutrin0_consensus_engine::Engine::genesis(spec, FaultDatabase::default()).unwrap();
    let ordinary = ChainBackend::new(engine, FixtureVerifier);
    assert_eq!(ordinary.light_health(), None);
}

#[tokio::test]
async fn backend_jumps_without_headers_and_restores_the_same_trust_expiry() {
    use neutrin0_network::rpc::role_flags;
    use neutrin0_rpc::RpcBackend;
    use neutrin0_sync::SyncBackend;
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time);
    assert_eq!(
        backend.local_metadata().await.role_flags,
        role_flags::LIGHT_CLIENT
    );
    let proof = jump(&origin);
    // Genesis trust needs no opening: the receipt proves the chain from it.
    let imported = backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    assert_eq!(imported.new_finalized_height, 3);
    let endpoint = proof.end_checkpoint();
    let head = backend.head().await.unwrap();
    assert_eq!((head.height, head.hash), (3, endpoint.boundary.block_hash));
    let progress = backend.local_progress().await.unwrap();
    assert_eq!(progress.finalized_chunks(), 3);
    assert_eq!(progress.checkpoint_hash, endpoint.hash());
    assert_eq!(progress.head_height, 3);
    assert_eq!(progress.finalized_state_root, endpoint.boundary.state_root);
    assert_eq!(progress.proven_height, 0);
    backend.with_engine(|engine| {
        assert_eq!(engine.head_height(), 0);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert!(engine.store().db().inner.is_empty(Column::Headers));
    });
    let before = snapshot(&backend);
    let persisted = database(&backend);
    let keys: Vec<_> = persisted
        .last_batch
        .iter()
        .map(|op| match op {
            neutrin0_storage::BatchOp::Put { column, key, .. } => (*column, key.as_slice()),
            neutrin0_storage::BatchOp::Delete { .. } => panic!("unexpected delete"),
            neutrin0_storage::BatchOp::AddCount { .. } => panic!("unexpected count"),
        })
        .collect();
    assert_eq!(
        keys,
        vec![(Column::Meta, STATE_KEY), (Column::Meta, PROOF_KEY)]
    );
    // A light node serves its genesis-rooted proof to a peer that needs
    // no opening, and opens nothing: a peer anchored elsewhere, which
    // cannot advance without one, is told so at once.
    let served = backend.history_proof(0, 3, endpoint.hash()).await.unwrap();
    assert_eq!((served.proof, served.anchor), (proof.clone(), None));
    assert!(matches!(
        backend.history_proof(1, 3, endpoint.hash()).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    assert_eq!(snapshot(&backend), before);
    assert_eq!(
        database(&backend).successful_batches,
        persisted.successful_batches
    );

    let engine = neutrin0_consensus_engine::Engine::open(spec.clone(), persisted).unwrap();
    let restarted = ChainBackend::new(engine, FixtureVerifier);
    assert_eq!(
        restarted.local_metadata().await.role_flags,
        role_flags::FULL_NODE
    );
    restarted
        .initialize_light(origin, spec.genesis_time, 30)
        .unwrap();
    assert_eq!(
        restarted.local_metadata().await.role_flags,
        role_flags::LIGHT_CLIENT
    );
    assert_eq!(snapshot(&restarted), before);
    assert_eq!(
        restarted
            .history_proof(0, 3, endpoint.hash())
            .await
            .unwrap()
            .proof,
        proof
    );
    assert_eq!(restarted.local_progress().await.unwrap(), progress);
    assert_eq!(restarted.head().await.unwrap(), head);
}

#[tokio::test]
async fn backend_rejects_expired_and_unreceipted_updates_without_mutation() {
    use neutrin0_sync::SyncBackend;
    let now = timestamp().unwrap();
    let spec = chain_spec(now);
    let (backend, origin) = backend(&spec, spec.genesis_time);
    let proof = jump(&origin);
    let initial = snapshot(&backend);
    let persisted = database(&backend).inner;
    let mut bad_receipt = proof.clone();
    bad_receipt.receipt = BoundedBytes::new(vec![]).unwrap();
    assert!(matches!(
        backend.verify_and_import_history(bad_receipt, None).await,
        Err(SyncBackendError::Rejected(_))
    ));
    assert_eq!(snapshot(&backend), initial);
    assert_eq!(database(&backend).inner, persisted);

    let (expired, _) = self::backend(
        &spec,
        now - spec.light_client.weak_subjectivity_period_secs - 1,
    );
    let before = snapshot(&expired);
    assert!(matches!(
        expired.verify_and_import_history(proof, None).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    assert_eq!(snapshot(&expired), before);
}

#[tokio::test]
async fn a_later_proof_advances_only_with_an_opening_and_never_backwards() {
    use neutrin0_sync::SyncBackend;
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time);
    let proof = jump(&origin);
    backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    // Past genesis, a later receipt is accepted only with an opening of
    // the current endpoint under it: sampling alone never places the
    // anchor on its chain.
    let (later, opening) = opened_jump(&origin, 5, 21, proof.end());
    assert!(matches!(
        backend.verify_and_import_history(later.clone(), None).await,
        Err(SyncBackendError::Rejected(_))
    ));
    backend
        .verify_and_import_history(later.clone(), Some(opening))
        .await
        .unwrap();
    assert_eq!(backend.light_checkpoint(), Some(later.end_checkpoint()));
    let advanced = snapshot(&backend);
    let persisted = database(&backend).inner;
    assert!(matches!(
        backend.verify_and_import_history(proof, None).await,
        Err(SyncBackendError::Rejected(_))
    ));
    assert_eq!(snapshot(&backend), advanced);
    assert_eq!(database(&backend).inner, persisted);
    assert!(!backend.light_halted());
}

#[tokio::test]
async fn verified_conflicting_endpoints_halt_durably_until_trust_is_replaced() {
    use neutrin0_sync::SyncBackend;
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time);
    let proof = jump(&origin);
    backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    // Two verified sides at a count above the current one: the first is
    // only remembered, the second halts.
    let later = jump_to(&origin, 5, 21);
    let mut fork = later.statement.statement.clone();
    fork.end.block_hash = [99; 32];
    let fork = signed(fork.chain, &fork.start, &fork.end);
    assert!(
        !backend
            .verify_history_conflict(later.clone())
            .await
            .unwrap()
    );
    assert!(!backend.light_halted());
    let mut invalid = fork.clone();
    invalid.receipt = BoundedBytes::new(vec![]).unwrap();
    assert!(matches!(
        backend.verify_history_conflict(invalid).await,
        Err(SyncBackendError::Rejected(_))
    ));
    assert!(!backend.light_halted());
    assert!(backend.verify_history_conflict(fork.clone()).await.unwrap());
    assert!(backend.light_halted());
    assert!(backend.history_halted().await);
    assert!(backend.light_health().unwrap().halted);
    // Nothing moves a halted client, not even the agreed later endpoint.
    let checkpoint = backend.light_checkpoint();
    assert!(matches!(
        backend.verify_and_import_history(later.clone(), None).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    assert_eq!(backend.light_checkpoint(), checkpoint);
    let evidence: LightConflict = borsh::from_slice(
        &database(&backend)
            .inner
            .get(Column::Meta, CONFLICT_KEY)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(evidence.chunks, 5);
    assert_eq!(evidence.first, Some(later));
    assert_eq!(evidence.second, fork);

    // The halt survives restart under the same trust origin.
    let persisted = database(&backend);
    let engine = neutrin0_consensus_engine::Engine::open(spec.clone(), persisted.clone()).unwrap();
    let restarted = ChainBackend::new(engine, FixtureVerifier);
    restarted
        .initialize_light(origin, spec.genesis_time, 30)
        .unwrap();
    assert!(restarted.light_halted());
    assert_eq!(restarted.light_checkpoint(), checkpoint);

    // A newly configured trusted checkpoint replaces the halted state.
    let engine = neutrin0_consensus_engine::Engine::open(spec.clone(), persisted).unwrap();
    let replaced = ChainBackend::new(engine, FixtureVerifier);
    replaced
        .initialize_light(origin, spec.genesis_time + 1, 30)
        .unwrap();
    assert!(!replaced.light_halted());
    assert_eq!(replaced.light_checkpoint(), Some(origin));
    assert!(replaced.light_latest_proof().unwrap().is_none());
    assert!(
        database(&replaced)
            .inner
            .get(Column::Meta, CONFLICT_KEY)
            .unwrap()
            .is_none()
    );
    replaced
        .verify_and_import_history(proof, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_endpoint_contradicting_the_current_one_halts() {
    use neutrin0_sync::SyncBackend;
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time);
    let proof = jump(&origin);
    backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    let mut fork = proof.statement.statement.clone();
    fork.end.block_hash = [99; 32];
    let fork = signed(fork.chain, &fork.start, &fork.end);
    // The same endpoint again only confirms it.
    assert!(
        !backend
            .verify_history_conflict(proof.clone())
            .await
            .unwrap()
    );
    assert!(matches!(
        backend.verify_and_import_history(fork.clone(), None).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    assert!(backend.light_halted());
    let evidence: LightConflict = borsh::from_slice(
        &database(&backend)
            .inner
            .get(Column::Meta, CONFLICT_KEY)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        (evidence.chunks, evidence.first, evidence.second),
        (3, Some(proof), fork)
    );
}

#[tokio::test]
async fn failed_atomic_light_write_never_advances_memory_or_one_half_of_the_pair() {
    use neutrin0_sync::SyncBackend;
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time);
    let before = snapshot(&backend);
    let persisted = database(&backend);
    backend.with_engine_mut(|engine| engine.store_mut().db_mut().fail_next_batch = true);
    let proof = jump(&origin);
    assert!(matches!(
        backend.verify_and_import_history(proof.clone(), None).await,
        Err(SyncBackendError::Storage(_))
    ));
    assert_eq!(snapshot(&backend), before);
    assert_eq!(database(&backend).inner, persisted.inner);
    assert!(backend.light_latest_proof().unwrap().is_none());
    backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    assert_eq!(backend.light_checkpoint(), Some(proof.end_checkpoint()));
    assert_eq!(backend.light_latest_proof().unwrap(), Some(proof));
}

#[tokio::test]
async fn an_opening_extends_or_faults_and_its_absence_is_refused() {
    use neutrin0_sync::SyncBackend;
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time);
    let proof = jump(&origin);
    backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    let (later, opening) = opened_jump(&origin, 5, 21, proof.end());
    // A path that does not verify is the provider's fault: the update is
    // rejected and nothing moves or halts.
    let mut broken = opening.clone();
    broken.path.siblings[0][0] ^= 1;
    let before = snapshot(&backend);
    let persisted = database(&backend).inner;
    assert!(matches!(
        backend
            .verify_and_import_history(later.clone(), Some(broken))
            .await,
        Err(SyncBackendError::Rejected(_))
    ));
    assert_eq!(snapshot(&backend), before);
    assert_eq!(database(&backend).inner, persisted);
    assert!(!backend.light_halted());
    // A verified opening that starts from the current endpoint advances.
    backend
        .verify_and_import_history(later.clone(), Some(opening))
        .await
        .unwrap();
    assert_eq!(backend.light_checkpoint(), Some(later.end_checkpoint()));
    // A provider that cannot open the current endpoint is refused, and
    // the client asks another; nothing moves or halts.
    let further = jump_to(&origin, 6, 22);
    let before = snapshot(&backend);
    assert!(matches!(
        backend.verify_and_import_history(further, None).await,
        Err(SyncBackendError::Rejected(_))
    ));
    assert_eq!(snapshot(&backend), before);
    assert!(!backend.light_halted());
}

#[tokio::test]
async fn an_opening_refuting_the_current_endpoint_halts_with_its_evidence() {
    use neutrin0_sync::SyncBackend;
    let spec = chain_spec(timestamp().unwrap());
    let (backend, origin) = backend(&spec, spec.genesis_time);
    let proof = jump(&origin);
    backend
        .verify_and_import_history(proof.clone(), None)
        .await
        .unwrap();
    // The new chain's leaf at the current count started from another
    // boundary: both chains are proven, so the client halts.
    let other = ConsensusBoundary {
        block_hash: [99; 32],
        ..*proof.end()
    };
    let (fork, opening) = opened_jump(&origin, 5, 21, &other);
    let checkpoint = backend.light_checkpoint();
    assert!(matches!(
        backend
            .verify_and_import_history(fork.clone(), Some(opening.clone()))
            .await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    assert!(backend.light_halted());
    assert_eq!(backend.light_checkpoint(), checkpoint);
    let evidence: LightConflict = borsh::from_slice(
        &database(&backend)
            .inner
            .get(Column::Meta, CONFLICT_KEY)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        (
            evidence.chunks,
            evidence.first,
            evidence.second,
            evidence.opening
        ),
        (3, Some(proof), fork, Some(opening))
    );
}
