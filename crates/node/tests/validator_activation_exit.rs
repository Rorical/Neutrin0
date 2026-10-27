//! Validator activation and exit epoch FSM.
//!
//! Drives the full lifecycle of a runtime-registered validator
//! through the chunk validator transition:
//!
//! 1. **Registration.** A funded account calls
//!    `registerValidator(bytes,bytes,uint256)` on the staking interface
//!    with its BLS pubkey, proof-of-possession and initial collateral. The
//!    runtime stores the registration; the bridge picks it up at the next
//!    chunk close.
//!
//! 2. **Activation FSM.** Newly-registered validators enter the
//!    consensus active set with `activation_epoch = current_epoch +
//!    activation_delay_epochs` and `effective_stake = 0` — every
//!    existing eligibility filter (`slashed || effective_stake ==
//!    0`) excludes them naturally. After `activation_delay_epochs`
//!    chunks (with `epoch_length_in_chunks = 1`), the bridge
//!    promotes them to their runtime stake.
//!
//! 3. **Exit FSM.** When a runtime-registered validator's stake
//!    drops to zero (via `unstake` / `exit`), the bridge
//!    sets `exit_epoch = current_epoch + exit_delay_epochs` once.
//!    After the exit delay elapses, the same
//!    `effective_stake == 0` filter excludes them permanently.
//!
//! 4. **Bad-POP filtering.** Registrations whose BLS POP fails
//!    verification never enter the runtime index or the consensus active
//!    set.

use std::sync::Arc;

use alloy_primitives::Address;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, Hash, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_rpc::{BlockId, RpcBackend};
use neutrin0_runtime_system::{ValidatorRegistration, ValidatorSet};
#[path = "support/native_chunk.rs"]
pub mod native_chunk;
use native_chunk::NativeChunkTestSystem;
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_storage::MemoryDatabase;
#[path = "support/evm.rs"]
pub mod evm;

const CHAIN_ID: u64 = 0xACE_BEEF;
const GENESIS_STAKE: u128 = 1_000_000_000;
const DEPOSIT_AMOUNT: u128 = 500_000;
const ACTIVATION_DELAY_EPOCHS: u64 = 2;
const EXIT_DELAY_EPOCHS: u64 = 2;
const EPOCH_LENGTH_IN_CHUNKS: u64 = 1;

type ActivationBackend = ChainBackend<MemoryDatabase, NativeChunkTestSystem>;

/// System address of the Ethereum account for `seed`: the credentials a
/// seat registered or seeded from that account carries.
fn credentials_of(seed: u8) -> Hash {
    evm::system_address(evm::address_of(seed))
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0xA7; 32], 0).expect("derive proposer key")
}

/// Build a `ProposerKey` representing the BLS identity for a
/// runtime-registered validator. The IKM seed lets each test slot
/// the registered validator on a deterministic BLS key.
fn registered_bls_key(seed: u8) -> ProposerKey {
    // `validator_index` is meaningless for a not-yet-active
    // validator; the bridge assigns the real index when the
    // validator is lifted into the active set. Use `1` so it
    // differs from the chain-spec proposer's index of `0`.
    ProposerKey::from_ikm(&[seed; 32], 1).expect("derive registered BLS key")
}

fn chain_spec_validators(runtime_addr: Hash) -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: runtime_addr,
        effective_stake: GENESIS_STAKE,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

/// Runtime parameters whose stake floor admits the test's small deposit.
fn runtime_params() -> RuntimeParams {
    RuntimeParams {
        min_validator_stake: DEPOSIT_AMOUNT,
        ..RuntimeParams::default()
    }
}

fn build_chain_spec(runtime_addr: Hash) -> ChainSpec {
    let validators = chain_spec_validators(runtime_addr);
    let proof = ProofParams::default();
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Single chain-spec validator stays VRF-eligible every slot
        // — keeps proposer rotation out of the test's concern.
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        epoch_length_in_chunks: EPOCH_LENGTH_IN_CHUNKS,
        activation_delay_epochs: ACTIVATION_DELAY_EPOCHS,
        exit_delay_epochs: EXIT_DELAY_EPOCHS,
        ..ConsensusParams::default()
    };
    let vs_root = neutrin0_consensus_engine::validator_set_root(&validators);
    let genesis_block_hash = [0xCD; 32];
    ChainSpec {
        genesis_execution: NativeChunkTestSystem::execution_programs(),
        name: BoundedBytes::new(b"act-exit".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0x4E; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: runtime_params(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

/// Backend at a genesis that seats the chain-spec validator at
/// `chain_spec_seed`'s account (so it can receive proposer fees) and funds
/// `funded`'s accounts for registrations and their fees.
fn build_backend(funded: &[Address], chain_spec_seed: u8) -> Arc<ActivationBackend> {
    let mut spec = build_chain_spec(credentials_of(chain_spec_seed));
    let trie = evm::seal_genesis(&mut spec, evm::funded(funded));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.install_genesis_state(trie).expect("genesis state");
    let proof_system = NativeChunkTestSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::embedded().expect("wasm runtime"));
    backend.set_local_voter(proposer_key());
    backend
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn active_set(backend: &ActivationBackend) -> Vec<Validator> {
    rt().block_on(backend.active_validator_set())
}

fn query_validator_set(backend: &ActivationBackend) -> ValidatorSet {
    let resp = rt().block_on(async {
        backend
            .runtime_call("validator_set".to_string(), Vec::new(), &BlockId::Latest)
            .await
            .expect("runtime_call validator_set")
    });
    borsh::from_slice(&resp.payload).expect("decode ValidatorSet")
}

fn query_validator_registration(
    backend: &ActivationBackend,
    address: [u8; 32],
) -> Option<ValidatorRegistration> {
    let resp = rt().block_on(async {
        backend
            .runtime_call(
                "validator_registration".to_string(),
                address.to_vec(),
                &BlockId::Latest,
            )
            .await
            .expect("runtime_call validator_registration")
    });
    borsh::from_slice(&resp.payload).expect("decode Option<ValidatorRegistration>")
}

/// Signed call of the staking interface from the key for `seed`.
fn staking_call(seed: u8, nonce: u64, data: Vec<u8>) -> Vec<u8> {
    evm::system_call(
        seed,
        nonce,
        neutrin0_evm_runtime_core::addresses::STAKING,
        data,
        CHAIN_ID,
    )
}

/// Registration of `bls` by the account for `seed`, binding the proof of
/// possession to that account and bonding `deposit_amount` from it.
fn register_validator(seed: u8, bls: &ProposerKey, deposit_amount: u128, nonce: u64) -> Vec<u8> {
    staking_call(
        seed,
        nonce,
        evm::register_calldata(
            bls.public_key_bytes(),
            &bls.prove_registration(&credentials_of(seed)).to_bytes(),
            deposit_amount,
        ),
    )
}

/// Produce one block at `slot`, prove it, finalise its single-block
/// chunk (`chunk_size = 1`) and run the chunk validator transition.
fn produce_prove_finalize_rotate(
    backend: &ActivationBackend,
    proposer: &ProposerKey,
    slot: u64,
    chunk_id: u64,
) {
    let outcome = backend
        .try_produce_block(slot, proposer)
        .expect("try_produce_block")
        .expect("validator eligible");
    backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block");
    backend
        .finalize_chunk(chunk_id, proposer)
        .expect("finalize_chunk");
}

/// Find the entry in `active_set` whose `withdrawal_credentials`
/// equal `addr`. Panics if not found — the calling test pinned the
/// expectation.
fn find_by_addr(active_set: &[Validator], addr: Hash) -> &Validator {
    active_set
        .iter()
        .find(|v| v.withdrawal_credentials == addr)
        .expect("validator address present in active set")
}

/// Shared scenario fixture: a chain with one chain-spec validator and a
/// funded account whose registered validator has reached its
/// `activation_epoch` and is producing effective stake. Returns the backend
/// after block 3 has been finalised so the new validator is active.
fn build_activated_scenario(
    proposer: &ProposerKey,
    chain_spec_seed: u8,
    new_validator_seed: u8,
    new_bls: &ProposerKey,
) -> Arc<ActivationBackend> {
    let backend = build_backend(&[evm::address_of(new_validator_seed)], chain_spec_seed);

    // Block 1: submit + apply the registration.
    backend
        .submit_transaction(register_validator(
            new_validator_seed,
            new_bls,
            DEPOSIT_AMOUNT,
            0,
        ))
        .expect("admission accepts the registration");
    produce_prove_finalize_rotate(&backend, proposer, 1, 0);

    // Blocks 2 + 3: empty blocks; cross the activation epoch.
    produce_prove_finalize_rotate(&backend, proposer, 2, 1);
    produce_prove_finalize_rotate(&backend, proposer, 3, 2);

    backend
}

#[test]
fn register_validator_activates_after_delay() {
    let _ = tracing_subscriber::fmt::try_init();

    let chain_spec_seed = 0xA1;
    let new_validator_seed = 0xC3;
    let chain_spec_addr = credentials_of(chain_spec_seed);
    let new_validator_addr = credentials_of(new_validator_seed);
    let new_bls = registered_bls_key(0xC3);
    let proposer = proposer_key();

    let backend = build_backend(&[evm::address_of(new_validator_seed)], chain_spec_seed);

    // Sanity: genesis active set carries just the chain-spec
    // validator at full stake.
    let active = active_set(&backend);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].withdrawal_credentials, chain_spec_addr);
    assert_eq!(active[0].effective_stake, GENESIS_STAKE);
    assert_eq!(active[0].activation_epoch, 0);
    assert_eq!(active[0].exit_epoch, u64::MAX);

    // Block 1: submit the registration.
    backend
        .submit_transaction(register_validator(
            new_validator_seed,
            &new_bls,
            DEPOSIT_AMOUNT,
            0,
        ))
        .expect("admission accepts the registration");
    produce_prove_finalize_rotate(&backend, &proposer, 1, 0);

    // Runtime accepted the registration:
    let rt_set = query_validator_set(&backend);
    assert!(
        rt_set
            .entries
            .iter()
            .any(|e| e.address == new_validator_addr && e.stake == DEPOSIT_AMOUNT),
        "runtime validator_set must contain the new validator at the deposited stake",
    );
    let registration = query_validator_registration(&backend, new_validator_addr)
        .expect("the new validator's registration");
    assert_eq!(registration.address, new_validator_addr);
    assert_eq!(registration.bls_pubkey, *new_bls.public_key_bytes());

    // Bridge ran. Current epoch after chunk 0 = (0+1)/1 = 1.
    // New validator: activation_epoch = 1 + 2 = 3, effective_stake = 0.
    let active = active_set(&backend);
    assert_eq!(active.len(), 2, "rotation must add the new validator");
    let new_entry = find_by_addr(&active, new_validator_addr);
    assert_eq!(new_entry.activation_epoch, 3);
    assert_eq!(new_entry.exit_epoch, u64::MAX);
    assert_eq!(
        new_entry.effective_stake, 0,
        "pre-activation effective_stake must be zero"
    );
    assert_eq!(new_entry.pubkey, *new_bls.public_key_bytes());

    // Block 2: still pre-activation (current_epoch = 2 < 3).
    produce_prove_finalize_rotate(&backend, &proposer, 2, 1);
    let active = active_set(&backend);
    assert_eq!(find_by_addr(&active, new_validator_addr).effective_stake, 0,);

    // Block 3: crosses activation epoch (current_epoch = 3).
    produce_prove_finalize_rotate(&backend, &proposer, 3, 2);
    let active = active_set(&backend);
    let new_entry = find_by_addr(&active, new_validator_addr);
    assert_eq!(
        new_entry.effective_stake, DEPOSIT_AMOUNT,
        "current_epoch >= activation_epoch → effective_stake = runtime stake",
    );
    assert_eq!(new_entry.exit_epoch, u64::MAX, "no exit scheduled");
}

#[test]
#[ignore = "exit chunks seat two weighted validators (the exiting seat keeps its weight until the handoff epoch while its collateral stays slashably locked), so finalization needs a multi-node BFT driver; the single-voter harness only finalizes when the sole majority seat is the round leader"]
fn registered_validator_exits_after_unstake() {
    let _ = tracing_subscriber::fmt::try_init();

    let chain_spec_seed = 0xA2;
    let new_validator_seed = 0xC4;
    let chain_spec_addr = credentials_of(chain_spec_seed);
    let new_validator_addr = credentials_of(new_validator_seed);
    let new_bls = registered_bls_key(0xC4);
    let proposer = proposer_key();

    let backend =
        build_activated_scenario(&proposer, chain_spec_seed, new_validator_seed, &new_bls);

    // Block 4: validator drains their full deposit. Runtime removes
    // them from the set; bridge's pass-1 exit FSM engages.
    backend
        .submit_transaction(staking_call(
            new_validator_seed,
            1,
            evm::calldata(b"unstake(uint256)", &[evm::word(DEPOSIT_AMOUNT)]),
        ))
        .expect("admission accepts unstake");
    produce_prove_finalize_rotate(&backend, &proposer, 4, 3);

    // Runtime confirms the validator is gone.
    let rt_set = query_validator_set(&backend);
    assert!(
        rt_set
            .entries
            .iter()
            .all(|e| e.address != new_validator_addr),
        "runtime validator_set drops zero-stake validators",
    );

    // Bridge: current_epoch = 4, exit_epoch = 4 + 2 = 6. A full exit keeps
    // its last authenticated weight until the scheduled handoff, while the
    // unbonding delay keeps its collateral unwithdrawable.
    let active = active_set(&backend);
    let new_entry = find_by_addr(&active, new_validator_addr);
    assert_eq!(new_entry.exit_epoch, 6, "exit_epoch = current + delay");
    assert_eq!(
        new_entry.effective_stake, DEPOSIT_AMOUNT,
        "exit weight is retained until the handoff",
    );

    // Block 5: exit is one-shot — second rotation must not rewrite.
    produce_prove_finalize_rotate(&backend, &proposer, 5, 4);
    let active = active_set(&backend);
    let new_entry = find_by_addr(&active, new_validator_addr);
    assert_eq!(new_entry.exit_epoch, 6, "exit_epoch must be one-shot");

    // Block 6: crosses exit_epoch (current_epoch = 6 = exit_epoch). Once
    // expired, the exit stops consuming a committee seat.
    produce_prove_finalize_rotate(&backend, &proposer, 6, 5);
    let active = active_set(&backend);
    assert!(
        active
            .iter()
            .all(|v| v.withdrawal_credentials != new_validator_addr),
        "current_epoch >= exit_epoch → seat released",
    );

    // Chain-spec validator must be untouched by the FSM throughout
    // (they never enter the auto-exit path because activation_epoch
    // == 0 is the discriminator).
    let chain_entry = find_by_addr(&active, chain_spec_addr);
    assert_eq!(chain_entry.activation_epoch, 0);
    assert_eq!(chain_entry.exit_epoch, u64::MAX);
    assert_eq!(chain_entry.effective_stake, GENESIS_STAKE);
}

#[test]
fn register_validator_with_invalid_pop_is_refused_by_the_runtime() {
    let _ = tracing_subscriber::fmt::try_init();

    let chain_spec_seed = 0xD1;
    let bad_validator_seed = 0xF3;
    let chain_spec_addr = credentials_of(chain_spec_seed);
    let bad_validator_addr = credentials_of(bad_validator_seed);
    let valid_bls = registered_bls_key(0xF3);
    let attacker_bls = registered_bls_key(0xAA);

    let backend = build_backend(&[evm::address_of(bad_validator_seed)], chain_spec_seed);
    let proposer = proposer_key();

    // Build a registration whose POP is forged: the POP signature is
    // generated by `attacker_bls` but bound to `valid_bls.public_key_bytes()`.
    // Execution's registration proof check rejects this: the signature does
    // not verify under the claimed pubkey, so the key is neither reserved nor
    // backed by unseatable stake.
    let valid_pubkey = *valid_bls.public_key_bytes();
    let attacker_pop = attacker_bls
        .prove_registration(&bad_validator_addr)
        .to_bytes();
    let bytes = staking_call(
        bad_validator_seed,
        0,
        evm::register_calldata(&valid_pubkey, &attacker_pop, DEPOSIT_AMOUNT),
    );

    // Admission leaves the pairing to execution, where the failed
    // registration still pays its fee.
    backend
        .submit_transaction(bytes)
        .expect("admission accepts; execution verifies the POP");

    produce_prove_finalize_rotate(&backend, &proposer, 1, 0);

    assert!(
        query_validator_registration(&backend, bad_validator_addr).is_none(),
        "the runtime records no registration with an invalid POP"
    );
    assert!(
        query_validator_set(&backend)
            .entries
            .iter()
            .all(|e| e.address != bad_validator_addr),
        "the refused registration bonds no stake"
    );
    let active = active_set(&backend);
    assert_eq!(
        active.len(),
        1,
        "no bad-POP registration reaches the active set"
    );
    assert_eq!(active[0].withdrawal_credentials, chain_spec_addr);
    assert!(
        active.iter().all(|v| v.pubkey != valid_pubkey),
        "the claimed BLS pubkey must not appear in the active set",
    );
}
