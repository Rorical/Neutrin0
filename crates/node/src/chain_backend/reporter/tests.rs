use super::*;
use neutrin0_consensus_engine::{Engine, RetentionPolicy};
use neutrin0_proof_system::MockProofSystem;
use neutrin0_runtime_core::host::LiveTrie;
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_runtime_system::{Validator, encode_validator, validator_key};
use neutrin0_storage::{Batch, Column, MemoryDatabase};
use std::sync::atomic::Ordering;

/// Executor fixture whose execution installs a chosen post-state: the
/// block's header commits exactly that trie.
struct InstallState(Trie);

impl neutrin0_proof_system::ErasedBlockExecutor for InstallState {
    fn execute_block(
        &self,
        _context: &neutrin0_proof_system::BlockExecutionContext,
        body: &neutrin0_consensus_types::Body,
        state: &mut Trie,
    ) -> Result<neutrin0_proof_system::ExecutionOutcome, String> {
        *state = self.0.clone();
        Ok(neutrin0_proof_system::ExecutionOutcome {
            artifacts: body.artifacts.clone(),
            state_root_after: self.0.root(),
            runtime_extra: [0; 32],
            receipts_root: body.artifacts.commitment(),
            gas_used: 0,
            witness_bytes: Vec::new(),
            state_writes: Vec::new(),
        })
    }

    fn query(
        &self,
        _request: &neutrin0_runtime_abi::QueryRequest,
        _runtime: Hash,
        _state: &Trie,
    ) -> Result<neutrin0_runtime_abi::QueryResponse, String> {
        Err("fixture answers no queries".into())
    }

    fn validate_tx(
        &self,
        _bytes: &[u8],
        _chain_id: u64,
        _gas_limit: u64,
        _runtime: Hash,
        _state: &Trie,
    ) -> Result<neutrin0_runtime_abi::TxValidity, String> {
        Err("fixture admits no transactions".into())
    }

    fn install_runtime(&self, _wasm: &[u8]) -> Result<Hash, String> {
        Err("fixture installs no artifacts".into())
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        Vec::new()
    }
}

fn finalized_genesis_backend() -> ChainBackend<MemoryDatabase, MockProofSystem> {
    let mut spec = super::super::state_sync_tests::spec();
    spec.runtime_code_hash = neutrin0_runtime_host::embedded_runtime_code_hash();
    let mut live = LiveTrie::default();
    live.insert(
        &validator_key(&spec.initial_validators[0].withdrawal_credentials),
        encode_validator(&Validator { stake: 123 }),
    );
    spec.genesis_state_root = live.state_root();
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
    engine.install_genesis_state(live.trie().clone()).unwrap();
    engine.set_programs(neutrin0_consensus_types::history_proof::GuestPrograms {
        execution: neutrin0_consensus_types::history_proof::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        chunk: [4; 8],
    });
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    backend.set_block_executor(WasmExecutor::embedded().unwrap());
    backend
}

#[test]
fn finalized_metrics_query_is_cached_and_missing_runtime_is_unavailable() {
    let backend = finalized_genesis_backend();
    backend.refresh_reporter_metrics();
    backend.refresh_reporter_metrics();
    let mut out = String::new();
    backend.metrics.reporter.render(&mut out);
    assert!(out.contains("neutrin0_accountability_metrics_available 1"));
    assert!(out.contains("neutrin0_accountability_query_total{outcome=\"ok\"} 1"));
    assert!(out.contains("neutrin0_accountability_deducted_total{kind=\"slash\"} 0"));
    let missing = finalized_genesis_backend();
    *missing.block_executor.lock().unwrap() = None;
    missing.refresh_reporter_metrics();
    out.clear();
    missing.metrics.reporter.render(&mut out);
    assert!(out.contains("neutrin0_accountability_metrics_available 0"));
    assert!(!out.contains("neutrin0_accountability_deducted_total"));
    assert_eq!(
        missing
            .metrics
            .reporter
            .economic_query_failures
            .load(Ordering::Relaxed),
        1
    );
}

fn add_tracked_identity(
    backend: &ChainBackend<MemoryDatabase, MockProofSystem>,
    pubkey: neutrin0_primitives::BlsPublicKey,
    address: Address,
) {
    backend.with_engine_mut(|engine| {
        let mut batch = Batch::new();
        batch.put(
            Column::ReporterValidators,
            pubkey,
            borsh::to_vec(&vec![address]).unwrap(),
        );
        engine
            .store_mut()
            .write_observed_batch(batch, true)
            .unwrap();
    });
}

#[test]
fn new_tracked_identity_refreshes_eligibility_at_unchanged_finalized_boundary() {
    let backend = finalized_genesis_backend();
    backend
        .initialize_reporter(neutrin0_primitives::runtime_account([9; 20]))
        .unwrap();
    let original = backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap());
    let finalized = backend.with_engine(neutrin0_consensus_engine::Engine::finalized_next_chunk_id);
    let mut initial = String::new();
    backend.metrics.reporter.render(&mut initial);
    assert!(initial.contains("neutrin0_reporter_eligibility_query_total{outcome=\"ok\"} 1"));

    // A late authenticated historical source can reintroduce an identity
    // whose account has already withdrawn. Finality need not advance.
    add_tracked_identity(&backend, [42; 48], [43; 32]);
    backend.refresh_reporter_tracking();
    assert_eq!(
        backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap()),
        original
    );
    assert_eq!(
        backend.with_engine(neutrin0_consensus_engine::Engine::finalized_next_chunk_id),
        finalized
    );
    // The cache stores the generation after cleanup, so its own deletion
    // does not trigger another query on the next monitor tick.
    backend.refresh_reporter_tracking();
    let mut out = String::new();
    backend.metrics.reporter.render(&mut out);
    assert!(out.contains("neutrin0_reporter_eligibility_query_total{outcome=\"ok\"} 2"));
    assert_eq!(
        backend
            .metrics
            .reporter
            .query_failures
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn new_funded_identity_during_query_prevents_stale_eligibility_cleanup() {
    let backend = finalized_genesis_backend();
    backend
        .initialize_reporter(neutrin0_primitives::runtime_account([9; 20]))
        .unwrap();
    let snapshot = backend
        .reporter_tracking_snapshot(None, None)
        .unwrap()
        .unwrap();
    let eligible: Vec<_> = snapshot
        .identities
        .iter()
        .map(|identity| (identity.pubkey, identity.withdrawal_credentials))
        .collect();

    // Runtime execution happens outside the engine lock. Another source
    // can authenticate a second BLS identity sharing the funded account
    // after the request was captured, but before its result is applied.
    let late = ([42; 48], eligible[0].1);
    add_tracked_identity(&backend, late.0, late.1);
    let before = backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap());
    assert!(before.contains(&late));
    assert!(
        backend
            .commit_reporter_eligibility(&snapshot, &eligible)
            .is_err()
    );
    assert_eq!(
        backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap()),
        before
    );

    // A fresh query classifies both accounts and keeps both funded owners.
    backend.refresh_reporter_tracking();
    assert_eq!(
        backend.with_engine(|engine| engine.reporter_tracked_validators().unwrap()),
        before
    );
}

#[test]
fn unfinalized_head_cannot_release_reporter_material() {
    let backend = finalized_genesis_backend();
    let header_hash = backend.with_engine_mut(|engine| {
        use neutrin0_consensus_engine::{ProposerKey, body::compute_body_roots};
        use neutrin0_consensus_types::{Block, Body, Header};
        let signer = ProposerKey::from_ikm(&[6; 32], 0).unwrap();
        let domain = engine.chain_spec().consensus_domain();
        let body = Body::default();
        let roots = compute_body_roots(&body);
        let speculative = Trie::new();
        // A signed, unfinalized header claims a post-state without stake.
        // Import it before restoring that head's trie, preserving the snap
        // installation invariant. The funded genesis remains finalized.
        let mut header = Header {
            height: 1,
            slot: 1,
            parent_hash: engine.head_hash(),
            proposer_index: 0,
            vrf_proof: signer.vrf_eval(domain, &engine.finalized_seed(), 1),
            state_root: speculative.root(),
            transactions_root: roots.transactions_root,
            votes_root: roots.votes_root,
            da_root: roots.da_root,
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
            receipts_root: neutrin0_consensus_types::Body::default()
                .artifacts
                .commitment(),
            gas_used: 0,
            gas_limit: engine.chain_spec().genesis_gas_limit,
            timestamp: engine.clock().timestamp_for(1),
            signature: [0; 96],
        };
        header.inputs_root = engine.expected_inputs_root(&header, &body).unwrap();
        header.signature = signer.sign_proposer_message(domain, &header.hash());
        let hash = header.hash();
        engine
            .import_block(&Block { header, body }, &InstallState(speculative))
            .unwrap();
        assert_eq!(engine.head_height(), 1);
        assert_eq!(engine.finalized_next_chunk_id(), 0);
        assert_eq!(engine.state().root(), engine.head_state_root());
        assert_ne!(
            engine.head_state_root(),
            engine.chain_spec().genesis_state_root
        );
        hash
    });
    backend
        .initialize_reporter(neutrin0_primitives::runtime_account([9; 20]))
        .unwrap();
    let identities =
        backend.with_engine(|engine| engine.store().reporter_tracked_validators().unwrap());
    assert_eq!(identities.len(), 1);
    assert_eq!(
        backend.reporter_recipient(),
        Some(neutrin0_primitives::runtime_account([9; 20]))
    );
    assert!(
        backend
            .with_engine(|engine| engine.store().reporter_header(&header_hash).unwrap())
            .is_some()
    );
}

#[test]
fn unavailable_finalized_state_preserves_tracking() {
    let backend = finalized_genesis_backend();
    backend
        .initialize_reporter(neutrin0_primitives::runtime_account([9; 20]))
        .unwrap();
    let identities =
        backend.with_engine(|engine| engine.store().reporter_tracked_validators().unwrap());
    backend.with_engine_mut(|engine| {
        let root = engine.chain_spec().genesis_state_root;
        engine
            .store_mut()
            .db_mut()
            .delete(Column::TrieNodes, &root)
            .unwrap();
    });
    backend
        .initialize_reporter(neutrin0_primitives::runtime_account([9; 20]))
        .unwrap();
    assert_eq!(
        backend.with_engine(|engine| { engine.store().reporter_tracked_validators().unwrap() }),
        identities
    );
}

#[test]
fn pending_rewards_keep_identity_after_tombstone_until_execution() {
    let identity = ReporterIdentity {
        pubkey: [3; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([4; 20]),
    };
    let pending = ReporterStatus {
        identity,
        slashable_balance: 0,
        tombstoned: true,
        pending: true,
    };
    assert_eq!(
        eligible_identities(&[identity], &[pending]).unwrap(),
        vec![(identity.pubkey, identity.withdrawal_credentials)]
    );
    let executed = ReporterStatus {
        pending: false,
        ..pending
    };
    assert_eq!(
        eligible_identities(&[identity], &[executed]).unwrap(),
        [] as [([u8; 48], [u8; 32]); 0]
    );
}

#[test]
fn actual_withdrawal_controls_retention_and_query_order_is_authenticated() {
    let identity = ReporterIdentity {
        pubkey: [5; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([6; 20]),
    };
    let bonded = ReporterStatus {
        identity,
        slashable_balance: 7,
        tombstoned: false,
        pending: false,
    };
    assert_eq!(
        eligible_identities(&[identity], &[bonded]).unwrap().len(),
        1
    );
    let withdrawn = ReporterStatus {
        slashable_balance: 0,
        ..bonded
    };
    assert_eq!(
        eligible_identities(&[identity], &[withdrawn]).unwrap(),
        [] as [([u8; 48], [u8; 32]); 0]
    );
    let other = ReporterIdentity {
        pubkey: [8; 48],
        ..identity
    };
    assert!(eligible_identities(&[other], &[bonded]).is_err());
    assert!(eligible_identities(&[identity], &[]).is_err());
}
