//! Candidate blocks and receipts travel separately (design 08).
//!
//! A producer publishes its candidate as soon as it has executed and its
//! receipt once proven. A follower holds the candidate as pending state:
//! `pending` advances, `latest` (the proven head) waits for the receipt, a
//! receipt ahead of its block waits in the orphan buffer, a tampered receipt
//! leaves the candidate in place, a candidate past its exclusive window stops
//! selecting the head until its receipt arrives, an executing node can
//! prove a candidate it did not produce, the proposer's receipt is relayed
//! after another receipt proved its block, and any node keeps the invalid
//! execution claim a receipt contradicting its header supports.

#[path = "support/evm.rs"]
pub mod evm;
#[path = "support/proven.rs"]
pub mod proven;

use std::sync::Arc;

use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{BlockState, ProposerKey};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_rpc::{BlockId, RpcBackend};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
use neutrin0_storage::{Column, Database};
use neutrin0_sync::{ReceiptsImported, SyncBackend, SyncBackendError};
use proven::{candidate_and_receipt, import_candidates_blocking, import_receipts_blocking};
use sp1_sdk::blocking::MockProver;

const CHAIN_ID: u64 = 314_160;
const GENESIS_SEED: [u8; 32] = [0xCE; 32];

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xB3; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xB3),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xEF; 32];
    let consensus = ConsensusParams {
        chunk_size: 4,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"candidate-receipts".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: neutrin0_runtime_host::package::embedded_chunk_program()
            .expect("embedded chunk Guest"),
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    })
}

async fn build_backend(follow: bool) -> Arc<Backend> {
    tokio::task::spawn_blocking(move || {
        let engine = evm::genesis_engine(chain_spec(), MemoryDatabase::new(), Vec::new());
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::embedded().expect("wasm runtime");
        backend.set_block_executor(executor);
        if follow {
            backend.enable_proof_follow().expect("proof following");
        }
        backend
    })
    .await
    .expect("spawn_blocking build backend")
}

/// A produced and proven block on a fresh producer, split as the network
/// carries it.
async fn produced(
    slot: u64,
) -> (
    Arc<Backend>,
    neutrin0_consensus_types::CandidateBlock,
    neutrin0_consensus_types::BlockReceipt,
) {
    let producer = build_backend(false).await;
    let hash = tokio::task::spawn_blocking({
        let producer = Arc::clone(&producer);
        move || {
            proven::produce_publication(&producer, slot, &proposer())
                .block
                .hash()
        }
    })
    .await
    .expect("spawn_blocking produce");
    let (candidate, receipt) = candidate_and_receipt(&producer, &hash);
    (producer, candidate, receipt)
}

/// A receipt of `candidate` that a third party proved under its own account.
async fn third_party_receipt(
    candidate: &neutrin0_consensus_types::CandidateBlock,
) -> neutrin0_consensus_types::BlockReceipt {
    let hash = candidate.block.hash();
    let third_party = build_backend(false).await;
    import_candidates_blocking(&third_party, vec![candidate.clone()])
        .await
        .expect("candidate imports");
    third_party.set_prove_foreign_blocks(true);
    third_party.set_prover_address(neutrin0_primitives::runtime_account([0x77; 20]));
    tokio::task::spawn_blocking({
        let third_party = Arc::clone(&third_party);
        move || {
            third_party
                .prove_block(&hash)
                .expect("foreign candidate proves")
        }
    })
    .await
    .expect("spawn_blocking prove");
    third_party
        .receipt_for_publication(&hash)
        .expect("the third-party receipt is ready")
}

/// `honest` with one written value altered, its header committing the root
/// those writes reproduce over its ancestors `parents` and signed again by the
/// proposer: a candidate whose writes are consistent but whose execution is not.
fn forge_results(
    parents: &[neutrin0_consensus_types::CandidateBlock],
    honest: &neutrin0_consensus_types::CandidateBlock,
) -> neutrin0_consensus_types::CandidateBlock {
    let mut forged = honest.clone();
    forged
        .writes
        .iter_mut()
        .find_map(|write| write.value.as_mut())
        .expect("the block writes a value")
        .push(0x5A);
    let genesis = evm::genesis_engine(chain_spec(), MemoryDatabase::new(), Vec::new());
    let mut state = genesis.state().clone();
    let mut root = ZERO_HASH;
    for writes in parents
        .iter()
        .map(|parent| &parent.writes)
        .chain([&forged.writes])
    {
        let diff = neutrin0_consensus_types::BlockStateDiff {
            height: 0,
            block_hash: ZERO_HASH,
            state_root_before: ZERO_HASH,
            state_root_after: ZERO_HASH,
            writes: writes.clone(),
        };
        root = neutrin0_consensus_engine::import::apply_state_diff::<()>(&mut state, &diff)
            .expect("writes apply");
    }
    let header = &mut forged.block.header;
    header.state_root = root;
    header.signature =
        proposer().sign_proposer_message(chain_spec().consensus_domain(), &header.hash());
    forged
}

/// The invalid execution claim `backend` persisted against `header_hash`.
fn persisted_claim(
    backend: &Backend,
    header_hash: &BlockHash,
) -> Option<neutrin0_consensus_types::SlashingEvidence> {
    let key = [b"execution-claim:".as_slice(), header_hash.as_slice()].concat();
    backend
        .snapshot_database()
        .get(Column::Meta, &key)
        .expect("metadata reads")
        .map(|bytes| borsh::from_slice(&bytes).expect("persisted claim decodes"))
}

async fn resolve(backend: &Arc<Backend>, id: BlockId) -> BlockHash {
    backend
        .resolve_block_id(&id)
        .await
        .expect("resolve block id")
        .expect("block id resolves")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_advances_pending_and_the_receipt_advances_latest() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_producer, candidate, receipt) = produced(1).await;
    let hash = candidate.block.hash();

    for follow in [true, false] {
        let follower = build_backend(follow).await;
        let genesis = follower.local_status().await.unwrap().head_block_hash;

        let imported = import_candidates_blocking(&follower, vec![candidate.clone()])
            .await
            .expect("candidate imports");
        assert_eq!(imported.new_head_hash, hash);
        assert_eq!(follower.block_state(&hash), Some(BlockState::BlockProduced));
        assert_eq!(follower.local_progress().await.unwrap().proven_height, 0);
        assert_eq!(resolve(&follower, BlockId::Latest).await, hash);
        assert_eq!(
            resolve(&follower, BlockId::Safe).await,
            genesis,
            "follow = {follow}: safe waits for the receipt",
        );
        // The same candidate again changes nothing.
        let again = import_candidates_blocking(&follower, vec![candidate.clone()])
            .await
            .expect("duplicate candidate is idempotent");
        assert_eq!(again.new_head_hash, hash);

        let receipts = import_receipts_blocking(&follower, vec![receipt.clone()])
            .await
            .expect("receipt imports");
        assert_eq!(receipts.proven, vec![1]);
        assert_eq!(receipts.buffered, 0);
        assert_eq!(follower.block_state(&hash), Some(BlockState::Proven));
        assert_eq!(follower.local_progress().await.unwrap().proven_height, 1);
        assert_eq!(resolve(&follower, BlockId::Safe).await, hash);
        // A duplicate receipt is neither an error nor a new proof.
        let duplicate = import_receipts_blocking(&follower, vec![receipt.clone()])
            .await
            .expect("duplicate receipt is harmless");
        assert_eq!(duplicate.proven, Vec::<u64>::new());
        assert!(follower.engine_state_invariant_holds());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receipt_ahead_of_its_candidate_waits_and_then_applies() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_producer, candidate, receipt) = produced(1).await;
    let hash = candidate.block.hash();
    let follower = build_backend(true).await;

    let early = import_receipts_blocking(&follower, vec![receipt.clone()])
        .await
        .expect("an orphan receipt is kept, not rejected");
    assert_eq!(early.proven, Vec::<u64>::new());
    assert_eq!(early.buffered, 1);
    assert_eq!(follower.orphan_receipt_count(), 1);
    assert_eq!(follower.block_state(&hash), None);

    import_candidates_blocking(&follower, vec![candidate])
        .await
        .expect("candidate imports");
    assert_eq!(
        follower.block_state(&hash),
        Some(BlockState::Proven),
        "the buffered receipt applies as soon as its block arrives",
    );
    assert_eq!(follower.orphan_receipt_count(), 0);
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_receipt_is_rejected_and_the_candidate_stays_pending() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_producer, candidate, mut receipt) = produced(1).await;
    let hash = candidate.block.hash();
    let follower = build_backend(true).await;
    import_candidates_blocking(&follower, vec![candidate])
        .await
        .expect("candidate imports");

    receipt.proof_bytes[0] ^= 0xFF;
    let err = import_receipts_blocking(&follower, vec![receipt])
        .await
        .expect_err("a tampered receipt is rejected");
    assert!(matches!(err, SyncBackendError::Rejected(_)), "{err:?}");
    assert_eq!(follower.block_state(&hash), Some(BlockState::BlockProduced));
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 0);
    assert_eq!(resolve(&follower, BlockId::Latest).await, hash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_candidate_leaves_the_head_until_a_late_receipt_restores_it_or_it_is_deleted() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_producer, candidate, receipt) = produced(1).await;
    let hash = candidate.block.hash();
    for restored in [true, false] {
        let follower = build_backend(true).await;
        let genesis = follower.local_status().await.unwrap().head_block_hash;
        import_candidates_blocking(&follower, vec![candidate.clone()])
            .await
            .expect("candidate imports");
        assert_eq!(follower.local_status().await.unwrap().head_block_hash, hash);
        let window = follower
            .with_engine_mut_for_test(|engine| engine.chain_spec().consensus.proof_exclusive_slots);

        // Its exclusive window has passed: the head leaves it, and it stays
        // archived for one more window so a late receipt can still prove it.
        follower.with_engine_mut_for_test(|engine| {
            engine.refresh_stale_candidates(1 + window, None).unwrap();
        });
        assert_eq!(
            follower.local_status().await.unwrap().head_block_hash,
            genesis
        );
        assert_eq!(follower.block_state(&hash), Some(BlockState::BlockProduced));

        if restored {
            // A valid late receipt restores it (design 08 case 11): it is
            // proven, the head returns to it and it is never deleted.
            import_receipts_blocking(&follower, vec![receipt.clone()])
                .await
                .expect("a valid late receipt verifies");
            assert_eq!(follower.block_state(&hash), Some(BlockState::Proven));
            follower.with_engine_mut_for_test(|engine| {
                engine
                    .refresh_stale_candidates(1 + 2 * window, None)
                    .unwrap();
            });
            assert_eq!(follower.local_status().await.unwrap().head_block_hash, hash);
            assert_eq!(follower.block_state(&hash), Some(BlockState::Proven));
        } else {
            // Without one, one window later the candidate and its records
            // are deleted.
            follower.with_engine_mut_for_test(|engine| {
                engine
                    .refresh_stale_candidates(1 + 2 * window, None)
                    .unwrap();
            });
            assert_eq!(follower.block_state(&hash), None);
            // Its signed header stays durably for abandonment detection.
            let kept = follower
                .with_engine_mut_for_test(|engine| engine.store().abandoned_headers(1, 1).unwrap());
            assert_eq!(
                kept.iter()
                    .map(neutrin0_consensus_types::Header::hash)
                    .collect::<Vec<_>>(),
                vec![hash]
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_executing_node_can_prove_a_candidate_it_did_not_produce() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_producer, candidate, _receipt) = produced(1).await;
    let hash = candidate.block.hash();

    // Following nodes hold no witness for the candidate and cannot prove it.
    let following = build_backend(true).await;
    import_candidates_blocking(&following, vec![candidate.clone()])
        .await
        .expect("candidate imports");
    assert!(
        tokio::task::spawn_blocking({
            let following = Arc::clone(&following);
            move || following.prove_block(&hash).is_err()
        })
        .await
        .expect("spawn_blocking prove"),
        "a following node has no witness to prove a foreign candidate",
    );

    // An executing node re-executed the candidate and retained its witness.
    let executing = build_backend(false).await;
    import_candidates_blocking(&executing, vec![candidate])
        .await
        .expect("candidate imports");
    executing.set_prove_foreign_blocks(true);
    assert!(executing.prove_foreign_blocks());
    tokio::task::spawn_blocking({
        let executing = Arc::clone(&executing);
        move || {
            executing
                .prove_block(&hash)
                .expect("foreign candidate proves")
        }
    })
    .await
    .expect("spawn_blocking prove");
    assert_eq!(executing.block_state(&hash), Some(BlockState::Proven));
    let receipt = executing
        .receipt_for_publication(&hash)
        .expect("the receipt is ready to publish");
    assert_eq!(receipt.block_hash, hash);

    // The receipt it produced proves the candidate on the following node.
    let imported = import_receipts_blocking(&following, vec![receipt])
        .await
        .expect("third-party receipt imports");
    assert_eq!(imported.proven, vec![1]);
    assert_eq!(following.block_state(&hash), Some(BlockState::Proven));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_retained_receipt_of_a_block_is_served_canonical_first() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_producer, candidate, proposers) = produced(1).await;
    let hash = candidate.block.hash();

    // A third party proves the same candidate under its own account.
    let third_party = build_backend(false).await;
    import_candidates_blocking(&third_party, vec![candidate.clone()])
        .await
        .expect("candidate imports");
    third_party.set_prove_foreign_blocks(true);
    let prover = neutrin0_primitives::runtime_account([0x77; 20]);
    third_party.set_prover_address(prover);
    let status = third_party.proving_status();
    assert!(status.prove_foreign_blocks);
    assert_eq!(
        status.prover_address,
        Some(neutrin0_rpc::HashHex::from(prover))
    );
    assert_eq!(status.pending_block_proofs, 1);
    tokio::task::spawn_blocking({
        let third_party = Arc::clone(&third_party);
        move || {
            third_party
                .prove_block(&hash)
                .expect("foreign candidate proves")
        }
    })
    .await
    .expect("spawn_blocking prove");
    let foreign = third_party
        .receipt_for_publication(&hash)
        .expect("the third-party receipt is ready");
    assert_ne!(foreign.proof_bytes, proposers.proof_bytes);

    // A follower retains both statements and serves both, the proposer's
    // canonical receipt first, so a voter can fetch the one a proposal names.
    let follower = build_backend(true).await;
    import_candidates_blocking(&follower, vec![candidate])
        .await
        .expect("candidate imports");
    import_receipts_blocking(&follower, vec![proposers.clone(), foreign.clone()])
        .await
        .expect("both receipts import");
    let served = follower
        .receipts_by_hash(&[hash])
        .await
        .expect("receipts are served");
    assert_eq!(served.receipts, vec![proposers, foreign]);
    assert_eq!(follower.proving_status().proven_head_height, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proposers_receipt_is_relayed_after_another_receipt_proved_its_block() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_producer, candidate, proposers) = produced(1).await;
    let foreign = third_party_receipt(&candidate).await;
    let follower = build_backend(true).await;
    import_candidates_blocking(&follower, vec![candidate])
        .await
        .expect("candidate imports");

    let first = import_receipts_blocking(&follower, vec![foreign.clone()])
        .await
        .expect("the third-party receipt imports");
    assert_eq!(first.proven, vec![1]);
    assert_eq!(first.relayed, 0);

    // Selection prefers the proposer's receipt, so it is relayed although
    // the block is already proven.
    let second = import_receipts_blocking(&follower, vec![proposers.clone()])
        .await
        .expect("the proposer's receipt imports");
    assert_eq!(second.proven, Vec::<u64>::new());
    assert_eq!(second.relayed, 1);

    // Neither receipt is relayed again.
    let repeat = import_receipts_blocking(&follower, vec![proposers, foreign])
        .await
        .expect("repeated receipts import");
    assert_eq!(repeat, ReceiptsImported::default());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn any_node_keeps_the_claim_a_receipt_contradicting_its_header_supports() {
    keeps_the_claim_against_a_forged_block(2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_against_the_first_block_names_the_genesis_boundary_as_its_parent() {
    keeps_the_claim_against_a_forged_block(1).await;
}

/// Forge the block at `height` and check that an executing node and a
/// following node both keep the claim its honest receipt supports. The first
/// block's parent is the genesis boundary, which has no header.
async fn keeps_the_claim_against_a_forged_block(height: u64) {
    let _ = tracing_subscriber::fmt::try_init();
    let producer = build_backend(false).await;
    let hashes = tokio::task::spawn_blocking({
        let producer = Arc::clone(&producer);
        move || {
            (1..=height)
                .map(|slot| {
                    proven::produce_publication(&producer, slot, &proposer())
                        .block
                        .hash()
                })
                .collect::<Vec<_>>()
        }
    })
    .await
    .expect("spawn_blocking produce");
    let (offending, ancestors) = hashes.split_last().expect("a forged block");
    let parents: Vec<_> = ancestors
        .iter()
        .map(|hash| candidate_and_receipt(&producer, hash).0)
        .collect();
    let (honest, _) = candidate_and_receipt(&producer, offending);
    let forged = forge_results(&parents, &honest);
    let forged_hash = forged.block.hash();
    let expected_parent = parents.last().map(|parent| parent.block.header.clone());

    // An executing node sees the execution contradict writes that reproduce
    // the header's root: it ignores the candidate and proves the honest
    // execution of the forged header.
    let executing = build_backend(false).await;
    if !parents.is_empty() {
        import_candidates_blocking(&executing, parents.clone())
            .await
            .expect("the parents import");
    }
    // Imported on the test runtime, which keeps running the proof job the
    // import spawns.
    let err = executing
        .verify_and_import_candidates(vec![forged.clone()])
        .await
        .expect_err("a diverging candidate is not imported by an executing node");
    assert!(
        matches!(&err, SyncBackendError::NotAvailable(reason)
            if reason.contains("execution contradicts the header")),
        "{err:?}"
    );
    let mut proven = None;
    for _ in 0..600 {
        proven = persisted_claim(&executing, &forged_hash);
        if proven.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let Some(neutrin0_consensus_types::SlashingEvidence::InvalidExecutionClaim {
        header,
        parent,
        receipt,
        ..
    }) = proven
    else {
        panic!("the executing node proves the honest execution: {proven:?}");
    };
    assert_eq!(header, forged.block.header);
    assert_eq!(parent, expected_parent);

    // A following node accepts the forged candidate on its writes and,
    // without executing anything, keeps the claim the honest receipt supports.
    let follower = build_backend(true).await;
    let mut chain = parents;
    chain.push(forged.clone());
    import_candidates_blocking(&follower, chain)
        .await
        .expect("the forged writes reproduce the forged root");
    let err = import_receipts_blocking(
        &follower,
        vec![neutrin0_consensus_types::BlockReceipt {
            block_hash: forged_hash,
            proof_bytes: receipt.proof_bytes,
        }],
    )
    .await
    .expect_err("the honest receipt does not prove the forged header");
    assert!(matches!(err, SyncBackendError::Rejected(_)), "{err:?}");
    assert_eq!(
        follower.block_state(&forged_hash),
        Some(BlockState::BlockProduced)
    );
    assert!(matches!(
        persisted_claim(&follower, &forged_hash),
        Some(neutrin0_consensus_types::SlashingEvidence::InvalidExecutionClaim { header, parent, .. })
            if header == forged.block.header && parent == expected_parent
    ));
}
