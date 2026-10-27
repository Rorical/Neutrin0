//! End-to-end validator lifecycle: stake → unstake → withdraw.
//!
//! Drives every staking path of the EVM runtime through real block
//! production against the staking interface at the runtime-owned address:
//!
//! - `stake(uint256)` bonds more of a seated validator's own balance.
//! - `unstake(uint256)` schedules a withdrawal at
//!   `current_height + UNBONDING_DELAY_BLOCKS` without crediting balance.
//! - `withdraw()` before maturity is a no-op for the balance but still
//!   consumes its nonce and gas.
//! - `withdraw()` at or past maturity drains every matured entry into
//!   spendable balance.
//! - `header.receipts_root` is the runtime's artifact commitment for the
//!   block; the proof's cross-check on `prove_block` would reject any header
//!   whose `receipts_root` drifts from the runtime-emitted value.

use std::sync::Arc;

use alloy_primitives::{Address, U256};
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, Hash, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_rpc::{BlockId, RpcBackend};
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_runtime_system::{Validator as RuntimeValidator, WithdrawalQueue};
#[path = "support/native_chunk.rs"]
pub mod native_chunk;
use native_chunk::NativeChunkTestSystem;
use neutrin0_storage::MemoryDatabase;
#[path = "support/evm.rs"]
pub mod evm;

const CHAIN_ID: u64 = 9001;
/// The shortest delay the exit rule admits: one exit epoch of one chunk plus
/// the two chunks an exiting seat still signs into.
const UNBONDING_DELAY_BLOCKS: u64 = 12;
const CHUNK_SIZE: u64 = 4;
const VALIDATOR_SEED: u8 = 2;
const GENESIS_STAKE: u128 = 32_000_000_000_000_000_000;
/// Collateral the lifecycle bonds and releases: far above the fee of any
/// fixture system call, so balance movements separate cleanly from fees.
const AMOUNT: u128 = 1_000_000_000_000;
/// Upper bound on one fixture system call's fee: its gas limit at the signed
/// fee cap.
const MAX_FEE: u128 = 400_000 * 1_000;

type LifecycleBackend = ChainBackend<MemoryDatabase, NativeChunkTestSystem>;

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0x5A; 32], 0).expect("derive proposer")
}

fn validator() -> Address {
    evm::address_of(VALIDATOR_SEED)
}

/// System address of the lifecycle validator: the seat's withdrawal
/// credentials and the key of its runtime stake record.
fn credentials() -> Hash {
    evm::system_address(validator())
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: credentials(),
        effective_stake: GENESIS_STAKE,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec_and_trie() -> (ChainSpec, neutrin0_trie::Trie) {
    // Genesis seeds the governable policy from the spec. The STF checks it
    // against the anchor's unbonding delay, so the short delay below needs
    // the matching short evidence window in state too.
    let runtime = RuntimeParams {
        unbonding_delay_blocks: UNBONDING_DELAY_BLOCKS,
        evidence_max_age_blocks: 2,
        min_validator_stake: 1,
        ..RuntimeParams::default()
    };
    let vs_root = neutrin0_consensus_engine::validator_set_root(&validators());
    let genesis_block_hash = [0xCC; 32];
    let proof = ProofParams::default();
    let consensus = ConsensusParams {
        chunk_size: CHUNK_SIZE,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        // Exit weight must retire before the short unbonding delay releases
        // its collateral: one epoch of one chunk is four blocks.
        exit_delay_epochs: 1,
        ..ConsensusParams::default()
    };
    let mut spec = ChainSpec {
        genesis_execution: NativeChunkTestSystem::execution_programs(),
        name: BoundedBytes::new(b"full-lifecycle".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0xAB; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams {
            // The trust window may not outlive this test's short safety window.
            weak_subjectivity_period_secs: 2 * neutrin0_primitives::DEFAULT_SLOT_DURATION_SECS,
            ..LightClientParams::default()
        },
        runtime,
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    let trie = evm::seal_genesis(&mut spec, evm::funded(&[validator()]));
    (spec, trie)
}

/// Header commitment of a candidate record holding `entries` without BLS identities.
fn candidates_root(entries: &[(Hash, u128)]) -> Hash {
    let mut candidates = neutrin0_consensus_types::runtime::ConsensusCandidates::default();
    for (address, stake) in entries {
        candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
            address: *address,
            stake: *stake,
            identity: None,
        });
    }
    candidates.root()
}

fn backend() -> Arc<LifecycleBackend> {
    let (spec, trie) = chain_spec_and_trie();
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.install_genesis_state(trie).expect("genesis state");
    let proof_system = NativeChunkTestSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::embedded().expect("wasm runtime"));
    backend
}

/// Signed call of the staking interface's `method` from the key for `seed`.
fn staking_call(seed: u8, nonce: u64, method: &[u8], words: &[[u8; 32]]) -> Vec<u8> {
    evm::system_call(
        seed,
        nonce,
        neutrin0_evm_runtime_core::addresses::STAKING,
        evm::calldata(method, words),
        CHAIN_ID,
    )
}

/// Submit `tx` through the mempool admission path; produce the next
/// slot's block, prove it, and return the produced header.
fn produce_with_tx(
    backend: &LifecycleBackend,
    proposer: &ProposerKey,
    slot: u64,
    tx: Vec<u8>,
) -> neutrin0_consensus_types::Header {
    backend.submit_transaction(tx).expect("admission accepts");
    let outcome = backend
        .try_produce_block(slot, proposer)
        .expect("try_produce_block")
        .expect("validator eligible");
    assert_eq!(
        outcome.block.body.transactions.len(),
        1,
        "the block carries the submitted call"
    );
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block");
    assert_eq!(
        proven.public_inputs.receipt_root, outcome.block.header.receipts_root,
        "the proof's cross-check matches the header's receipts_root",
    );
    outcome.block.header
}

/// Tokio runtime for `RpcBackend::runtime_call` (it's async).
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn runtime_call(backend: &LifecycleBackend, method: &str, args: Vec<u8>) -> Vec<u8> {
    let response = rt().block_on(async {
        backend
            .runtime_call(method.to_string(), args, &BlockId::Latest)
            .await
            .expect("runtime_call")
    });
    assert_eq!(
        response.code,
        neutrin0_runtime_abi::QueryStatus::Ok.as_u32(),
        "{method} succeeds"
    );
    response.payload
}

/// Nonce and wei of `address` at the head.
fn account(backend: &LifecycleBackend, address: Address) -> (u64, U256) {
    backend.with_engine_mut_for_test(|engine| evm::account_in(engine.state(), address))
}

/// Active stake of the runtime validator record at `credentials`.
fn stake_of(backend: &LifecycleBackend, credentials: Hash) -> u128 {
    let record: Option<RuntimeValidator> = borsh::from_slice(&runtime_call(
        backend,
        "validator_get",
        credentials.to_vec(),
    ))
    .expect("decode Option<Validator>");
    record.map_or(0, |record| record.stake)
}

fn query_pending_withdrawals(backend: &LifecycleBackend, credentials: Hash) -> WithdrawalQueue {
    borsh::from_slice(&runtime_call(
        backend,
        "pending_withdrawals",
        credentials.to_vec(),
    ))
    .expect("decode WithdrawalQueue")
}

/// `after` is `before` less `spent` and one call's fee.
fn assert_paid(before: U256, after: U256, spent: u128) {
    assert!(after < before, "the call paid a fee: {before} -> {after}");
    let delta = before - after;
    assert!(
        delta > U256::from(spent) && delta <= U256::from(spent + MAX_FEE),
        "paid {delta} for {spent} plus a fee under {MAX_FEE}",
    );
}

/// `after` is `before` plus `credited` less one call's fee.
fn assert_credited(before: U256, after: U256, credited: u128) {
    assert!(
        after > before,
        "the call credited funds: {before} -> {after}"
    );
    let delta = after - before;
    assert!(
        delta < U256::from(credited) && delta >= U256::from(credited - MAX_FEE),
        "credited {delta} for {credited} less a fee under {MAX_FEE}",
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One lifecycle: stake, unstake, early and mature withdraw.
fn stake_then_unstake_then_withdraw_round_trips_through_full_pipeline() {
    let backend = backend();
    let proposer = proposer_key();
    let credentials = credentials();
    let genesis_stake = GENESIS_STAKE;
    let (_, validator_start) = account(&backend, validator());
    assert_eq!(validator_start, U256::from(evm::FUNDS));
    assert_eq!(stake_of(&backend, credentials), genesis_stake);

    // Slot 1: the validator bonds AMOUNT more of its own balance.
    let h1 = produce_with_tx(
        &backend,
        &proposer,
        1,
        staking_call(VALIDATOR_SEED, 0, b"stake(uint256)", &[evm::word(AMOUNT)]),
    );
    assert_eq!(h1.height, 1);
    assert!(h1.gas_used > 0);
    assert_eq!(stake_of(&backend, credentials), genesis_stake + AMOUNT);
    // The consensus candidate record carries the bonded stake.
    assert_eq!(
        h1.runtime_extra,
        candidates_root(&[(credentials, genesis_stake + AMOUNT)])
    );
    // The validator produced block 1 and collected back its priority fee;
    // the base fee is escrowed.
    let (nonce, validator_after_stake) = account(&backend, validator());
    assert_eq!(nonce, 1);
    assert_paid(validator_start, validator_after_stake, AMOUNT);

    // Slot 2: the validator unstakes the added collateral; its seat keeps
    // the genesis stake.
    let h2 = produce_with_tx(
        &backend,
        &proposer,
        2,
        staking_call(VALIDATOR_SEED, 1, b"unstake(uint256)", &[evm::word(AMOUNT)]),
    );
    assert_eq!(stake_of(&backend, credentials), genesis_stake);
    assert_eq!(
        h2.runtime_extra,
        candidates_root(&[(credentials, genesis_stake)])
    );
    // Balance only paid the fee; the queue carries AMOUNT.
    let (nonce, after_unstake) = account(&backend, validator());
    assert_eq!(nonce, 2);
    assert_paid(validator_after_stake, after_unstake, 0);
    let queue = query_pending_withdrawals(&backend, credentials);
    assert_eq!(queue.entries.len(), 1);
    assert_eq!(queue.entries[0].amount, AMOUNT);
    assert_eq!(
        queue.entries[0].mature_at_height,
        2 + UNBONDING_DELAY_BLOCKS,
    );

    // Slot 3: early withdraw — nothing matured. Succeeds, consumes gas and a
    // nonce, but credits zero.
    produce_with_tx(
        &backend,
        &proposer,
        3,
        staking_call(VALIDATOR_SEED, 2, b"withdraw()", &[]),
    );
    let (nonce, after_early) = account(&backend, validator());
    assert_eq!(nonce, 3);
    assert_paid(after_unstake, after_early, 0);
    assert_eq!(
        query_pending_withdrawals(&backend, credentials)
            .entries
            .len(),
        1,
        "early withdraw did not drain the queue",
    );

    // Advance through proof-gated chunk boundaries using a short, internally
    // consistent test policy (evidence age + chunk size < unbonding delay).
    let mature_height = 2 + UNBONDING_DELAY_BLOCKS;
    let mut next_slot = 4u64; // slot 3 was the early withdraw
    while backend.head_height() < mature_height {
        let block = backend
            .try_produce_block(next_slot, &proposer)
            .unwrap()
            .unwrap();
        backend.prove_block(&block.block_hash).unwrap();
        if block.block.header.height.is_multiple_of(CHUNK_SIZE) {
            backend
                .finalize_chunk(block.block.header.height / CHUNK_SIZE - 1, &proposer)
                .unwrap();
        }
        next_slot += 1;
    }
    assert_eq!(backend.head_height(), mature_height);
    // Empty blocks move no nonce. As the chain's only producer, prover and
    // signer the validator gains the settlement of each consumed proving
    // report (design 08), including the escrowed fees of blocks 1 to 3.
    let (nonce, before_withdraw) = account(&backend, validator());
    assert_eq!(nonce, 3, "empty blocks move no nonce");
    assert!(
        before_withdraw > after_early,
        "settlement paid the sole prover: {after_early} -> {before_withdraw}",
    );

    // Submit the mature withdraw. The validator's nonce is 3 (bumped by the
    // stake, the unstake and the early withdraw).
    produce_with_tx(
        &backend,
        &proposer,
        next_slot,
        staking_call(VALIDATOR_SEED, 3, b"withdraw()", &[]),
    );

    // Final state: AMOUNT returned to balance, queue drained, seat intact.
    let (nonce, final_balance) = account(&backend, validator());
    assert_eq!(nonce, 4);
    assert_credited(before_withdraw, final_balance, AMOUNT);
    assert!(
        query_pending_withdrawals(&backend, credentials)
            .entries
            .is_empty(),
        "queue drained"
    );
    assert_eq!(stake_of(&backend, credentials), genesis_stake);
}
