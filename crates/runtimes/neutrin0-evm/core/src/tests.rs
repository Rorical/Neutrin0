//! Economic, rollback and witnessed execution acceptance tests.

use crate::{
    addresses,
    execution::{EvmBlockMetadata, ExecutionReceipt},
    genesis::{EvmGenesisConfig, GenesisAccount},
    state,
};
use alloc::{vec, vec::Vec};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::Signature;
use neutrin0_runtime_abi::{RuntimeBlockInput, RuntimeGenesisInput, RuntimeTransaction};
use neutrin0_runtime_core::{
    StateBackend, WitnessState,
    host::{LiveTrie, TracingState},
};
use revm::primitives::{Address, B256, TxKind, U256, keccak256};

fn sender() -> Address {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}
fn signed(nonce: u64, kind: TxKind, value: u128, data: Vec<u8>, gas: u64) -> RuntimeTransaction {
    let tx = TxEip1559 {
        chain_id: 7,
        nonce,
        gas_limit: gas,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        to: kind,
        value: U256::from(value),
        input: data.into(),
        ..Default::default()
    };
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let (sig, recovery) = key.sign_prehash_recoverable(tx.signature_hash().as_slice());
    let bytes = sig.to_bytes();
    let signature = Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    );
    RuntimeTransaction::User(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}
fn genesis(extra: Vec<GenesisAccount>) -> LiveTrie {
    genesis_with_balance(extra, U256::from(1_000_000_000_u64))
}

fn genesis_with_balance(extra: Vec<GenesisAccount>, balance: U256) -> LiveTrie {
    let empty = LiveTrie::default();
    let mut state = TracingState::new(&empty);
    let mut accounts = vec![GenesisAccount {
        address: sender().into_array(),
        balance: balance.to_be_bytes(),
        nonce: 0,
        code: Vec::new(),
        storage: Vec::new(),
    }];
    accounts.extend(extra);
    let input = RuntimeGenesisInput {
        max_block_proving_input_bytes: neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        chain_id: 7,
        timestamp: 0,
        seed: [8; 32],
        genesis_block_hash: [0; 32],
        chunk_size: neutrin0_primitives::DEFAULT_CHUNK_SIZE,
        programs: neutrin0_primitives::ProgramSet {
            runtime_code_hash: [0; 32],
            execution: neutrin0_primitives::ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
        },
        block_gas_limit: 1_000_000,
        runtime_params: neutrin0_primitives::RuntimeParams::default(),
        validators: Vec::new(),
        configuration: borsh::to_vec(&EvmGenesisConfig {
            initial_base_fee: 10,
            accounts,
        })
        .unwrap(),
    };
    crate::init_genesis(&input, &mut state);
    LiveTrie::from_trie(state.into_committed_and_witness().unwrap().0)
}
fn input(transactions: Vec<RuntimeTransaction>) -> RuntimeBlockInput {
    let mut input = RuntimeBlockInput {
        active_validators: Vec::new(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),
        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
        evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: 7,
        block_height: 1,
        block_gas_limit: 1_000_000,
        proposer_address: state::consensus_address(Address::from([9; 20])),
        participation: None,
        proving: None,
        transactions,
    };
    input.context.timestamp = 100;
    input.context.slot = 1;
    input.context.parent_block_hash = [6; 32];
    input.context.finalized.seed = [8; 32];
    input
}
fn account(live: &LiveTrie, address: Address) -> state::EvmAccount {
    state::load_account(&mut TracingState::new(live), address)
        .unwrap()
        .unwrap_or_default()
}
fn execute(
    live: &LiveTrie,
    input: &RuntimeBlockInput,
) -> (neutrin0_runtime_abi::RuntimeBlockResult, LiveTrie) {
    let mut state = TracingState::new(live);
    let result = crate::execute_block(input, &mut state);
    let (post, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    assert_eq!(crate::execute_block(input, &mut guest), result);
    assert_eq!(guest.post_state_root(), post.root());
    (result, LiveTrie::from_trie(post))
}
fn receipt(result: &neutrin0_runtime_abi::RuntimeBlockResult) -> crate::execution::EvmReceipt {
    let ExecutionReceipt::Ethereum(receipt) =
        borsh::from_slice(result.artifacts.receipts.last().unwrap()).unwrap()
    else {
        panic!("Ethereum receipt")
    };
    receipt
}

#[test]
fn transfer_pays_tips_to_the_proposer_and_escrows_the_base_fee() {
    let live = genesis(Vec::new());
    let destination = Address::from([4; 20]);
    let input = input(vec![signed(
        0,
        TxKind::Call(destination),
        123,
        Vec::new(),
        21_000,
    )]);
    let (result, post) = execute(&live, &input);
    let receipt = receipt(&result);
    assert!(receipt.success);
    assert_eq!(receipt.gas_used, 21_000);
    assert_eq!(receipt.effective_gas_price, 13);
    assert_eq!(
        account(&post, destination).balance,
        U256::from(123).to_be_bytes::<32>()
    );
    assert_eq!(account(&post, sender()).nonce, 1);
    assert_eq!(
        account(&post, sender()).balance,
        U256::from(1_000_000_000_u64 - 123 - 21_000 * 13).to_be_bytes::<32>()
    );
    // Design 08: the proposer keeps only the tip, 13 - 10 per gas; the base
    // fee is escrowed for the chunk prover and the participating committee.
    assert_eq!(
        account(&post, Address::from([9; 20])).balance,
        U256::from(21_000 * 3_u64).to_be_bytes::<32>()
    );
    let base_fees = u128::from(21_000 * 10_u64);
    let mut view = TracingState::new(&post);
    let escrow: neutrin0_runtime_system::proving::FeeEscrow = borsh::from_slice(
        &view
            .read(&neutrin0_runtime_system::proving::escrow_fees_key(
                input.block_height,
            ))
            .unwrap(),
    )
    .unwrap();
    // The first block only starts the issuance clock.
    assert_eq!(
        escrow,
        neutrin0_runtime_system::proving::FeeEscrow {
            committee: base_fees / 2,
            chunk_prover: base_fees / 2,
            block_prover: 0,
        }
    );
    let metadata: EvmBlockMetadata = borsh::from_slice(&result.artifacts.metadata).unwrap();
    assert_eq!(metadata.base_fee, 10);
    assert_eq!(metadata.context, input.context);
    assert_eq!(
        neutrin0_runtime_core::execution::artifacts_commitment(&result.artifacts),
        result.output.receipts_root
    );
}

#[test]
fn verification_skips_invalid_transactions_as_selection_does() {
    let live = genesis(Vec::new());
    let destination = Address::from([4; 20]);
    // A nonce gap, an undecodable payload and an allowance above the block
    // gas: each is skipped with no effects, so the block stays provable.
    let mut input = input(vec![
        signed(0, TxKind::Call(destination), 123, Vec::new(), 21_000),
        signed(2, TxKind::Call(destination), 5, Vec::new(), 21_000),
        RuntimeTransaction::User(vec![2, 0xc0]),
        signed(1, TxKind::Call(destination), 7, Vec::new(), u64::MAX / 2),
    ]);
    let mut state = TracingState::new(&live);
    assert_eq!(
        crate::execution::select_transactions(&input, &mut state).unwrap(),
        vec![0]
    );
    assert_eq!(state.post_state_root(), live.state_root());
    let (result, post) = execute(&live, &input);
    assert_eq!(result.artifacts.transaction_ids.len(), 1);
    assert_eq!(result.artifacts.transaction_ids[0].0, 0);
    assert_eq!((result.output.applied, result.output.failed), (1, 0));
    assert_eq!(account(&post, sender()).nonce, 1);
    assert_eq!(
        account(&post, destination).balance,
        U256::from(123).to_be_bytes::<32>()
    );
    // Only the valid transaction's effects: the block equals the one the
    // producer would have built from the selection.
    input.transactions.truncate(1);
    let (selected, selected_post) = execute(&live, &input);
    assert_eq!(post.state_root(), selected_post.state_root());
    assert_eq!(result.output.gas_used, selected.output.gas_used);
}

#[test]
fn deployment_storage_and_revert_charge_nonce_and_gas() {
    let live = genesis(Vec::new());
    // Init code returns a runtime which writes slot zero and then reverts.
    let runtime = vec![0x60, 0x2a, 0x5f, 0x55, 0x5f, 0x5f, 0xfd];
    let mut init = vec![0x60, 7, 0x60, 10, 0x5f, 0x39, 0x60, 7, 0x5f, 0xf3];
    init.extend(runtime);
    let (deployed, live) = execute(
        &live,
        &input(vec![signed(0, TxKind::Create, 0, init, 100_000)]),
    );
    let contract = Address::from(receipt(&deployed).contract_address.unwrap());
    let mut call = input(vec![signed(
        1,
        TxKind::Call(contract),
        10,
        Vec::new(),
        100_000,
    )]);
    call.block_height = 2;
    call.context.timestamp += 1;
    call.context.slot += 1;
    let (result, post) = execute(&live, &call);
    assert!(!receipt(&result).success);
    assert_eq!(account(&post, sender()).nonce, 2);
    assert_eq!(account(&post, contract).balance, [0; 32]);
    assert!(
        post.get(&state::storage_key(contract, U256::ZERO))
            .unwrap()
            .is_none()
    );
    assert!(receipt(&result).gas_used > 21_000);
}

#[test]
fn blocks_rewrite_the_chunk_environment_only_when_it_changes() {
    use crate::environment::{CHUNK_ENVIRONMENT_KEY, ENVIRONMENT_KEY};
    let written = |live: &LiveTrie, input: &RuntimeBlockInput| {
        let mut state = TracingState::new(live);
        crate::execute_block(input, &mut state);
        let (post, _, writes) = state.into_committed_witness_and_writes().unwrap();
        let keys: Vec<_> = writes.into_iter().map(|(key, _)| key).collect();
        (LiveTrie::from_trie(post), keys)
    };
    // Genesis already holds chunk zero's consensus set and no reports.
    let (live, keys) = written(&genesis(Vec::new()), &input(Vec::new()));
    assert!(keys.contains(&ENVIRONMENT_KEY.to_vec()));
    assert!(!keys.contains(&CHUNK_ENVIRONMENT_KEY.to_vec()));
    let mut next = input(Vec::new());
    next.block_height = 2;
    next.context.timestamp += 1;
    next.context.slot += 1;
    next.evidence_anchor.chunk_id = 1;
    let (live, keys) = written(&live, &next);
    assert!(keys.contains(&CHUNK_ENVIRONMENT_KEY.to_vec()));
    // Simulation still reads the latest block's environment in full.
    next.transactions.clear();
    assert_eq!(
        crate::environment::load(&mut TracingState::new(&live))
            .unwrap()
            .unwrap(),
        next
    );
}

#[test]
fn nested_system_stake_is_reverted_with_its_contract_frame() {
    let contract = Address::from([5; 20]);
    let validator = state::consensus_address(contract);
    let mut calldata = keccak256(b"stake(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&U256::from(100).to_be_bytes::<32>());
    // Copy embedded calldata, call the staking entrypoint, require success,
    // then revert the enclosing frame. CALL failure triggers INVALID.
    let mut code = vec![
        0x60, 36, 0x60, 31, 0x5f, 0x39, 0x5f, 0x5f, 0x60, 36, 0x5f, 0x5f, 0x61, 8, 0, 0x5a, 0xf1,
        0x60, 26, 0x57, 0xfe,
    ];
    code.resize(26, 0);
    code.extend([0x5b, 0x5f, 0x5f, 0xfd]);
    code.push(0);
    code.extend(calldata);
    let mut live = genesis(vec![GenesisAccount {
        address: contract.into_array(),
        balance: U256::from(1_000_000).to_be_bytes(),
        nonce: 1,
        code,
        storage: Vec::new(),
    }]);
    live.insert(
        &neutrin0_runtime_system::validator_key(&validator),
        borsh::to_vec(&neutrin0_runtime_system::Validator {
            stake: neutrin0_primitives::DEFAULT_MIN_VALIDATOR_STAKE,
        })
        .unwrap(),
    );
    let (result, post) = execute(
        &live,
        &input(vec![signed(
            0,
            TxKind::Call(contract),
            0,
            Vec::new(),
            900_000,
        )]),
    );
    let receipt = receipt(&result);
    assert!(!receipt.success);
    assert!(
        receipt.gas_used < 900_000,
        "stake succeeded before REVERT rather than hitting INVALID"
    );
    assert_eq!(receipt.logs, []);
    assert_eq!(
        post.get(&neutrin0_runtime_system::validator_key(&validator))
            .unwrap(),
        live.get(&neutrin0_runtime_system::validator_key(&validator))
            .unwrap()
    );
    assert_eq!(account(&post, contract), account(&live, contract));
    assert_eq!(
        account(&post, addresses::ESCROW),
        account(&live, addresses::ESCROW)
    );
}

#[test]
fn eip1559_adjustment_is_positive_and_counts_all_gas() {
    assert_eq!(crate::fees::next_base_fee(10, 500, 1_000), Ok(10));
    assert_eq!(crate::fees::next_base_fee(10, 1_000, 1_000), Ok(11));
    assert_eq!(crate::fees::next_base_fee(1, 0, 1_000), Ok(1));
}

fn sign_hash(hash: B256) -> Signature {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let (signature, recovery) = key.sign_prehash_recoverable(hash.as_slice());
    let bytes = signature.to_bytes();
    Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    )
}

#[test]
fn eip7702_delegation_advances_authority_nonce_and_executes_in_authority_storage() {
    use alloy_consensus::TxEip7702;
    use alloy_eips::eip7702::Authorization;
    let implementation = Address::from([5; 20]);
    let live = genesis(vec![GenesisAccount {
        address: implementation.into_array(),
        balance: [0; 32],
        nonce: 1,
        code: vec![0x60, 42, 0x5f, 0x55, 0x00],
        storage: Vec::new(),
    }]);
    // Sender's transaction nonce increments first; its authorization uses nonce 1.
    let authorization = Authorization {
        chain_id: U256::from(7),
        address: implementation,
        nonce: 1,
    };
    let authorization = authorization
        .clone()
        .into_signed(sign_hash(authorization.signature_hash()));
    let transaction = TxEip7702 {
        chain_id: 7,
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        to: sender(),
        authorization_list: vec![authorization],
        ..Default::default()
    };
    let signature = sign_hash(transaction.signature_hash());
    let transaction = RuntimeTransaction::User(
        TxEnvelope::from(transaction.into_signed(signature)).encoded_2718(),
    );
    let block = input(vec![
        transaction,
        signed(
            2,
            TxKind::Call(Address::from([4; 20])),
            5,
            Vec::new(),
            21_000,
        ),
    ]);
    let mut scratch = TracingState::new(&live);
    assert_eq!(
        crate::execution::select_transactions(&block, &mut scratch).unwrap(),
        vec![0, 1]
    );
    assert_eq!(scratch.post_state_root(), live.state_root());
    let (result, post) = execute(&live, &block);
    assert!(receipt(&result).success);
    assert_eq!(account(&post, sender()).nonce, 3);
    assert_eq!(
        post.get(&state::storage_key(sender(), U256::ZERO)).unwrap(),
        Some(U256::from(42).to_be_bytes::<32>().to_vec())
    );
    assert!(
        post.get(&state::storage_key(implementation, U256::ZERO))
            .unwrap()
            .is_none()
    );
    let record = account(&post, sender());
    let mut expected = vec![0xef, 0x01, 0x00];
    expected.extend_from_slice(implementation.as_slice());
    assert_eq!(
        post.get(&state::code_key(B256::from(record.code_hash)))
            .unwrap(),
        Some(expected)
    );
}

#[test]
fn protected_legacy_and_access_list_decode_but_unprotected_and_blob_are_rejected() {
    use alloy_consensus::{TxEip2930, TxEip4844, TxLegacy};
    let legacy = TxLegacy {
        chain_id: Some(7),
        nonce: 0,
        gas_limit: 21_000,
        gas_price: 13,
        to: TxKind::Call(Address::from([4; 20])),
        ..Default::default()
    };
    let raw = TxEnvelope::from(
        legacy
            .clone()
            .into_signed(sign_hash(legacy.signature_hash())),
    )
    .encoded_2718();
    assert!(crate::transaction::decode(&raw, 7).is_ok());
    assert!(crate::transaction::decode(&raw, 8).is_err());
    let unprotected = TxLegacy {
        chain_id: None,
        ..legacy
    };
    let raw = TxEnvelope::from(
        unprotected
            .clone()
            .into_signed(sign_hash(unprotected.signature_hash())),
    )
    .encoded_2718();
    assert!(crate::transaction::decode(&raw, 7).is_err());
    let access = TxEip2930 {
        chain_id: 7,
        nonce: 0,
        gas_limit: 30_000,
        gas_price: 13,
        to: TxKind::Call(Address::from([4; 20])),
        ..Default::default()
    };
    let raw = TxEnvelope::from(
        access
            .clone()
            .into_signed(sign_hash(access.signature_hash())),
    )
    .encoded_2718();
    assert!(crate::transaction::decode(&raw, 7).is_ok());
    let blob = TxEip4844 {
        chain_id: 7,
        ..Default::default()
    };
    let raw =
        TxEnvelope::from(blob.clone().into_signed(sign_hash(blob.signature_hash()))).encoded_2718();
    assert!(crate::transaction::decode(&raw, 7).is_err());
}

#[test]
fn pending_execution_uses_evolving_nonce_state_and_reports_proposer_vrf_unavailable() {
    use neutrin0_runtime_abi::{
        QueryRequest,
        ethereum::{PendingBlock, PendingMode, PendingRequest},
    };
    let live = genesis(Vec::new());
    let block = input(vec![
        signed(
            1,
            TxKind::Call(Address::from([4; 20])),
            5,
            Vec::new(),
            21_000,
        ),
        signed(
            0,
            TxKind::Call(Address::from([4; 20])),
            7,
            Vec::new(),
            21_000,
        ),
    ]);
    let mut state = TracingState::new(&live);
    let request = |query| QueryRequest {
        method: "evm:pending".into(),
        args: borsh::to_vec(&PendingRequest {
            mode: PendingMode::NextBlock,
            block: block.clone(),
            query,
        })
        .unwrap(),
    };
    let response = crate::query(
        &request(QueryRequest {
            method: "evm:block".into(),
            args: Vec::new(),
        }),
        &mut state,
    );
    assert!(response.is_ok(), "{response:?}");
    let pending: PendingBlock = borsh::from_slice(&response.payload).unwrap();
    assert_eq!(
        pending
            .transactions
            .iter()
            .map(|tx| tx.nonce)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let response = crate::query(
        &request(QueryRequest {
            method: "evm:account".into(),
            args: borsh::to_vec(&sender().into_array()).unwrap(),
        }),
        &mut state,
    );
    let account: state::EvmAccount = borsh::from_slice(&response.payload).unwrap();
    assert_eq!(account.nonce, 2);
    let call = crate::query::CallRequest {
        from: sender().into_array(),
        to: Some(addresses::CONSENSUS.into_array()),
        value: [0; 32],
        data: keccak256(b"producerVrf()")[..4].to_vec(),
        gas_limit: 100_000,
        fee_cap: None,
        tip_cap: None,
        access_list: Vec::new(),
        transaction_type: None,
        authorization_list: Vec::new(),
    };
    let response = crate::query(
        &request(QueryRequest {
            method: "evm:call".into(),
            args: borsh::to_vec(&call).unwrap(),
        }),
        &mut state,
    );
    let result: crate::query::CallResult = borsh::from_slice(&response.payload).unwrap();
    assert!(!result.success && result.reverted);
    assert_eq!(state.post_state_root(), live.state_root());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One head-local overlay regression checks projection, isolation and context forgery rejection."
)]
fn head_local_pending_keeps_authenticated_environment_and_disposes_all_writes() {
    use neutrin0_runtime_abi::{
        QueryRequest,
        ethereum::{PendingBlock, PendingMode, PendingRequest},
    };
    let live = genesis(Vec::new());
    let (_, head) = execute(&live, &input(Vec::new()));
    let environment = crate::environment::load(&mut TracingState::new(&head))
        .unwrap()
        .unwrap();
    let mut pending = environment.clone();
    let destination = Address::from([4; 20]);
    // A full-ceiling declaration allows only one transfer in this scratch view.
    // Admission/pool sequence queries independently retain every contiguous nonce.
    pending.transactions = (0..3)
        .map(|nonce| {
            signed(
                nonce,
                TxKind::Call(destination),
                7,
                Vec::new(),
                pending.block_gas_limit,
            )
        })
        .collect();
    let mut state = TracingState::new(&head);
    let request = |block: RuntimeBlockInput, query| QueryRequest {
        method: "evm:pending".into(),
        args: borsh::to_vec(&PendingRequest {
            mode: PendingMode::HeadLocal,
            block,
            query,
        })
        .unwrap(),
    };
    let response = crate::query(
        &request(
            pending.clone(),
            QueryRequest {
                method: "evm:block".into(),
                args: Vec::new(),
            },
        ),
        &mut state,
    );
    assert!(response.is_ok(), "{response:?}");
    let projection: PendingBlock = borsh::from_slice(&response.payload).unwrap();
    assert_eq!(projection.mode, PendingMode::HeadLocal);
    assert_eq!(projection.number, environment.block_height);
    assert_eq!(projection.metadata.context, environment.context);
    assert_eq!(projection.metadata.system_gas, 0);
    assert_eq!(projection.transactions.len(), 1);
    let response = crate::query(
        &request(
            pending.clone(),
            QueryRequest {
                method: "evm:account".into(),
                args: destination.to_vec(),
            },
        ),
        &mut state,
    );
    assert!(response.is_ok(), "{response:?}");
    let selected_account: state::EvmAccount = borsh::from_slice(&response.payload).unwrap();
    assert_eq!(selected_account.balance, U256::from(7).to_be_bytes::<32>());
    let response = crate::query(
        &request(
            pending.clone(),
            QueryRequest {
                method: "evm:environment".into(),
                args: Vec::new(),
            },
        ),
        &mut state,
    );
    assert!(response.is_ok(), "{response:?}");
    assert_eq!(
        borsh::from_slice::<RuntimeBlockInput>(&response.payload).unwrap(),
        environment
    );
    // Forging a future timestamp/height cannot turn this query mode into a block.
    pending.context.timestamp += 1;
    let response = crate::query(
        &request(
            pending,
            QueryRequest {
                method: "evm:block".into(),
                args: Vec::new(),
            },
        ),
        &mut state,
    );
    assert!(!response.is_ok());
    assert_eq!(state.post_state_root(), head.state_root());
    assert_eq!(account(&head, sender()).nonce, 0);
    assert_eq!(account(&head, destination).balance, [0; 32]);
}

/// Give `address` a weighted consensus seat in `input`'s authenticated set.
fn seat(input: &mut RuntimeBlockInput, address: Address) {
    let credential = state::consensus_address(address);
    input
        .active_validators
        .push(neutrin0_primitives::Validator {
            pubkey: [credential[31]; 48],
            withdrawal_credentials: credential,
            effective_stake: 1,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        });
    input.context.finalized.validators_root =
        neutrin0_consensus_types::evidence::commitment(&input.active_validators);
}
fn with_validator(mut live: LiveTrie, address: Address, stake: u128) -> LiveTrie {
    let credential = state::consensus_address(address);
    let previous_stake = live
        .get(&neutrin0_runtime_system::validator_key(&credential))
        .unwrap()
        .map_or(0, |bytes| {
            borsh::from_slice::<neutrin0_runtime_system::Validator>(&bytes)
                .unwrap()
                .stake
        });
    live.insert(
        &neutrin0_runtime_system::validator_key(&credential),
        borsh::to_vec(&neutrin0_runtime_system::Validator { stake }).unwrap(),
    );
    let mut candidates = live
        .get(neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY)
        .unwrap()
        .map(|bytes| {
            borsh::from_slice::<neutrin0_consensus_types::runtime::ConsensusCandidates>(&bytes)
                .unwrap()
        })
        .unwrap_or_default();
    candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
        address: credential,
        stake,
        identity: None,
    });
    live.insert(
        neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY,
        borsh::to_vec(&candidates).unwrap(),
    );
    let mut escrow = account(&live, addresses::ESCROW);
    escrow.balance = (U256::from_be_bytes(escrow.balance) - U256::from(previous_stake)
        + U256::from(stake))
    .to_be_bytes();
    live.insert(
        &state::account_key(addresses::ESCROW),
        borsh::to_vec(&escrow).unwrap(),
    );
    live.insert(
        neutrin0_runtime_system::RUNTIME_POLICY_KEY,
        borsh::to_vec(&neutrin0_runtime_system::RuntimePolicy {
            min_validator_stake: 1,
            ..neutrin0_runtime_system::RuntimePolicy::default()
        })
        .unwrap(),
    );
    live
}
fn system_call(name: &[u8], amount: Option<U256>) -> Vec<u8> {
    let mut data = keccak256(name)[..4].to_vec();
    if let Some(amount) = amount {
        data.extend(amount.to_be_bytes::<32>());
    }
    data
}
#[test]
fn staking_overflow_reverts_and_withdrawal_preserves_immature_funds() {
    let live = with_validator(genesis(Vec::new()), sender(), 100);
    let mut block = input(vec![
        signed(
            0,
            TxKind::Call(addresses::STAKING),
            0,
            system_call(b"stake(uint256)", Some(U256::from(50))),
            200_000,
        ),
        signed(
            1,
            TxKind::Call(addresses::STAKING),
            0,
            system_call(b"stake(uint256)", Some(U256::MAX)),
            200_000,
        ),
        signed(
            2,
            TxKind::Call(addresses::STAKING),
            0,
            system_call(b"exit()", None),
            200_000,
        ),
        signed(
            3,
            TxKind::Call(addresses::STAKING),
            0,
            system_call(b"withdraw()", None),
            200_000,
        ),
    ]);
    block.evidence_anchor.unbonding_delay_blocks =
        neutrin0_primitives::DEFAULT_UNBONDING_DELAY_BLOCKS;
    block.evidence_anchor.chunk_size = neutrin0_primitives::DEFAULT_CHUNK_SIZE;
    let (result, post) = execute(&live, &block);
    let receipts: Vec<ExecutionReceipt> = result
        .artifacts
        .receipts
        .iter()
        .map(|bytes| borsh::from_slice(bytes).unwrap())
        .collect();
    let succeeded: Vec<bool> = receipts
        .iter()
        .filter_map(|receipt| match receipt {
            ExecutionReceipt::Ethereum(receipt) => Some(receipt.success),
            ExecutionReceipt::System(_) => None,
        })
        .collect();
    assert_eq!(succeeded, vec![true, false, true, true]);
    assert_eq!(account(&post, sender()).nonce, 4);
    assert_eq!(
        U256::from_be_bytes(account(&post, addresses::ESCROW).balance),
        U256::from(150)
    );
    let validator: neutrin0_runtime_system::Validator = borsh::from_slice(
        &post
            .get(&neutrin0_runtime_system::validator_key(
                &state::consensus_address(sender()),
            ))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(validator.stake, 0);
    assert_eq!(validator.stake, 0);
    let withdrawal: neutrin0_runtime_system::WithdrawalQueue = borsh::from_slice(
        &post
            .get(&neutrin0_runtime_system::withdrawal_key(
                &state::consensus_address(sender()),
            ))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(withdrawal.entries[0].amount, 150);
    assert_eq!(
        withdrawal.entries[0].mature_at_height,
        1 + neutrin0_primitives::DEFAULT_UNBONDING_DELAY_BLOCKS
    );
}
#[test]
fn nested_governance_policy_enactment_and_logs_roll_back() {
    let contract = Address::from([5; 20]);
    let policy = neutrin0_runtime_system::RuntimePolicy {
        min_validator_stake: 1,
        chunk_prover_fee_bps: 2,
        ..neutrin0_runtime_system::RuntimePolicy::default()
    };
    let encoded = borsh::to_vec(&policy).unwrap();
    let mut data = system_call(b"proposePolicy(bytes)", Some(U256::from(32)));
    data.extend(U256::from(encoded.len()).to_be_bytes::<32>());
    data.extend(encoded);
    data.resize(data.len().div_ceil(32) * 32 + 4, 0);
    let length = u16::try_from(data.len()).unwrap().to_be_bytes();
    let mut code = vec![
        0x61, length[0], length[1], 0x61, 0, 29, 0x5f, 0x39, 0x5f, 0x5f, 0x61, length[0],
        length[1], 0x5f, 0x5f, 0x61, 8, 1, 0x5a, 0xf1, 0x61, 0, 25, 0x57, 0xfe, 0x5b, 0x5f, 0x5f,
        0xfd,
    ];
    code.extend(data);
    let live = with_validator(
        genesis(vec![GenesisAccount {
            address: contract.into_array(),
            balance: [0; 32],
            nonce: 1,
            code,
            storage: Vec::new(),
        }]),
        contract,
        100,
    );
    let mut block = input(vec![signed(
        0,
        TxKind::Call(contract),
        0,
        Vec::new(),
        900_000,
    )]);
    block.evidence_anchor.unbonding_delay_blocks =
        neutrin0_primitives::DEFAULT_UNBONDING_DELAY_BLOCKS;
    block.evidence_anchor.chunk_size = neutrin0_primitives::DEFAULT_CHUNK_SIZE;
    // Governance counts only validators consensus has seated.
    seat(&mut block, contract);
    let (result, post) = execute(&live, &block);
    let receipt = receipt(&result);
    assert!(!receipt.success);
    assert!(
        receipt.gas_used < 900_000,
        "inner governance call succeeded before outer revert"
    );
    assert_eq!(receipt.logs, []);
    assert_eq!(
        post.get(neutrin0_runtime_system::RUNTIME_POLICY_KEY)
            .unwrap(),
        live.get(neutrin0_runtime_system::RUNTIME_POLICY_KEY)
            .unwrap()
    );
    assert_eq!(
        post.get(neutrin0_runtime_system::governance::POLICY_PROPOSALS_KEY)
            .unwrap(),
        live.get(neutrin0_runtime_system::governance::POLICY_PROPOSALS_KEY)
            .unwrap()
    );
}
#[test]
fn eip7702_call_simulation_applies_authorizations_in_a_disposable_journal() {
    use alloy_eips::eip7702::Authorization;
    use neutrin0_runtime_abi::ethereum::{CallRequest, EvmAuthorization};
    let implementation = Address::from([5; 20]);
    let live = genesis(vec![GenesisAccount {
        address: implementation.into_array(),
        balance: [0; 32],
        nonce: 1,
        code: vec![0x60, 42, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3],
        storage: Vec::new(),
    }]);
    let authorization = Authorization {
        chain_id: U256::from(7),
        address: implementation,
        nonce: 1,
    };
    let signature = sign_hash(authorization.signature_hash());
    let request = CallRequest {
        from: sender().into_array(),
        to: Some(sender().into_array()),
        value: [0; 32],
        data: Vec::new(),
        gas_limit: 100_000,
        fee_cap: None,
        tip_cap: Some(3),
        access_list: Vec::new(),
        transaction_type: Some(4),
        authorization_list: vec![EvmAuthorization {
            chain_id: U256::from(7).to_be_bytes(),
            address: implementation.into_array(),
            nonce: 1,
            y_parity: u8::from(signature.v()),
            r: signature.r().to_be_bytes(),
            s: signature.s().to_be_bytes(),
        }],
    };
    let mut trace = TracingState::new(&live);
    let result = crate::query::simulate(&request, &mut trace).unwrap();
    assert!(result.success);
    assert_eq!(result.output, U256::from(42).to_be_bytes::<32>());
    assert_eq!(trace.post_state_root(), live.state_root());
    assert_eq!(account(&live, sender()).nonce, 0);
    assert_eq!(
        account(&live, sender()).code_hash,
        revm::primitives::KECCAK_EMPTY.0
    );
}

#[test]
fn pending_sanction_holds_matured_withdrawal_during_evm_calls() {
    use neutrin0_runtime_abi::ethereum::CallRequest;
    use neutrin0_runtime_system::accountability::PendingSanction;
    let mut live = with_validator(genesis(Vec::new()), sender(), 100);
    let credential = state::consensus_address(sender());
    live.insert(
        &neutrin0_runtime_system::withdrawal_key(&credential),
        borsh::to_vec(&neutrin0_runtime_system::WithdrawalQueue {
            entries: vec![neutrin0_runtime_system::Withdrawal {
                amount: 50,
                mature_at_height: 0,
            }],
        })
        .unwrap(),
    );
    let sanction = PendingSanction {
        sanction: neutrin0_consensus_types::runtime::Sanction {
            offence_id: [33; 32],
            offender: neutrin0_primitives::Validator {
                pubkey: [42; 48],
                withdrawal_credentials: credential,
                effective_stake: 100,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
            },
            kind: neutrin0_consensus_types::evidence::SanctionKind::Slash,
        },
        amount: 100,
        reporter: None,
        reporter_reward_bps: 0,
    };
    live.insert(
        neutrin0_runtime_system::accountability::QUEUE_KEY,
        borsh::to_vec(&vec![sanction]).unwrap(),
    );
    let request = CallRequest {
        from: sender().into_array(),
        to: Some(addresses::STAKING.into_array()),
        value: [0; 32],
        data: system_call(b"withdraw()", None),
        gas_limit: 200_000,
        fee_cap: None,
        tip_cap: None,
        access_list: Vec::new(),
        transaction_type: None,
        authorization_list: Vec::new(),
    };
    let mut trace = TracingState::new(&live);
    let result = crate::query::simulate(&request, &mut trace).unwrap();
    assert!(result.reverted);
    assert_eq!(trace.post_state_root(), live.state_root());
    live.insert(
        neutrin0_runtime_system::accountability::QUEUE_KEY,
        borsh::to_vec(&Vec::<PendingSanction>::new()).unwrap(),
    );
    let mut trace = TracingState::new(&live);
    assert!(
        crate::query::simulate(&request, &mut trace)
            .unwrap()
            .success
    );
    assert_eq!(trace.post_state_root(), live.state_root());
}

fn simulate_system(live: &LiveTrie, address: Address, data: Vec<u8>) -> crate::query::CallResult {
    let request = crate::query::CallRequest {
        from: sender().into_array(),
        to: Some(address.into_array()),
        value: [0; 32],
        data,
        gas_limit: 900_000,
        fee_cap: None,
        tip_cap: None,
        access_list: Vec::new(),
        transaction_type: None,
        authorization_list: Vec::new(),
    };
    let mut trace = TracingState::new(live);
    let result = crate::query::simulate(&request, &mut trace).unwrap();
    assert_eq!(trace.post_state_root(), live.state_root());
    result
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One typed proposal covers every policy field, its identity and the journaled views."
)]
fn typed_governance_returns_proposal_identity_and_exposes_journaled_status() {
    let mut live = with_validator(
        with_validator(genesis(Vec::new()), sender(), 100),
        Address::from([4; 20]),
        100,
    );
    // Simulation runs under the stored head environment, whose authenticated
    // consensus seats decide governance eligibility.
    let mut environment = crate::environment::load(&mut TracingState::new(&live))
        .unwrap()
        .unwrap();
    seat(&mut environment, sender());
    seat(&mut environment, Address::from([4; 20]));
    let (_, chunk) = crate::environment::records(&environment);
    live.insert(
        crate::environment::CHUNK_ENVIRONMENT_KEY,
        borsh::to_vec(&chunk).unwrap(),
    );
    // Every field travels in the tuple, the proof-market splits included.
    let policy = neutrin0_runtime_system::RuntimePolicy {
        min_validator_stake: 2,
        chunk_prover_fee_bps: 1_500,
        annual_issuance_bps: 300,
        ..neutrin0_runtime_system::RuntimePolicy::default()
    };
    let values = [
        policy.min_validator_stake,
        u128::from(policy.evidence_max_age_blocks),
        u128::from(policy.evidence_max_pending),
        u128::from(policy.evidence_admissions_per_block),
        u128::from(policy.evidence_executions_per_block),
        policy.inactivity_leak_amount,
        u128::from(policy.reporter_reward_bps),
        u128::from(policy.chunk_prover_fee_bps),
        u128::from(policy.annual_issuance_bps),
        policy.abandonment_penalty_amount,
    ];
    let mut data = system_call(
        b"proposePolicy((uint128,uint64,uint32,uint32,uint32,uint128,uint16,uint16,uint16,uint128))",
        None,
    );
    for value in values {
        data.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    }
    let id = neutrin0_runtime_system::governance::proposal_id(
        &state::consensus_address(sender()),
        &neutrin0_runtime_system::ProposalAction::Policy(policy),
    );
    let simulation = simulate_system(&live, addresses::GOVERNANCE, data.clone());
    assert!(simulation.success);
    assert_eq!(simulation.output, id);
    let mut block = input(vec![signed(
        0,
        TxKind::Call(addresses::GOVERNANCE),
        0,
        data,
        900_000,
    )]);
    seat(&mut block, sender());
    seat(&mut block, Address::from([4; 20]));
    let (result, post) = execute(&live, &block);
    let receipt = receipt(&result);
    assert!(receipt.success);
    assert_eq!(receipt.logs.len(), 2);
    assert_eq!(receipt.logs[1].topics[2], id);
    let count = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(b"policyProposalCount()", None),
    );
    assert_eq!(count.output, U256::from(1).to_be_bytes::<32>());
    let proposal = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(b"policyProposalAt(uint256)", Some(U256::ZERO)),
    );
    assert!(proposal.success);
    assert_eq!(proposal.output.len(), 6 * 32);
    assert_eq!(proposal.output[..32], U256::from(1).to_be_bytes::<32>());
    assert_eq!(proposal.output[32..64], id);
    assert_eq!(proposal.output[96..128], U256::from(1).to_be_bytes::<32>());
    let beyond = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(b"policyProposalAt(uint256)", Some(U256::MAX)),
    );
    assert_eq!(beyond.output, [0; 6 * 32]);
    let voted = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(
            b"hasVoted(address)",
            Some(U256::from_be_bytes(state::consensus_address(sender()))),
        ),
    );
    assert!(voted.success);
    assert_eq!(voted.output, U256::from(1).to_be_bytes::<32>());
    let enacted = simulate_system(&post, addresses::GOVERNANCE, system_call(b"policy()", None));
    assert!(enacted.success);
    assert_eq!(
        enacted.output[..32],
        U256::from(1).to_be_bytes::<32>(),
        "an open policy proposal does not change the enacted policy"
    );
    let scheduled = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(b"scheduledUpgrade()", None),
    );
    assert!(scheduled.success);
    assert_eq!(scheduled.output, vec![0; 11 * 32]);
}

#[test]
fn fork_proposals_travel_through_the_governance_interface() {
    let other = Address::from([4; 20]);
    let live = with_validator(
        with_validator(genesis(Vec::new()), sender(), 100),
        other,
        100,
    );
    let count = neutrin0_runtime_system::governance::upgrade_min_lead_chunks(
        &neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
    );
    let fork = neutrin0_primitives::ScheduledFork {
        count,
        successor: [5; 32],
    };
    let mut data = system_call(b"proposeFork(uint64,bytes32)", Some(U256::from(count)));
    data.extend_from_slice(&fork.successor);
    let id = neutrin0_runtime_system::governance::proposal_id(
        &state::consensus_address(sender()),
        &neutrin0_runtime_system::ProposalAction::Fork(fork),
    );
    let mut block = input(vec![signed(
        0,
        TxKind::Call(addresses::GOVERNANCE),
        0,
        data,
        900_000,
    )]);
    seat(&mut block, sender());
    seat(&mut block, other);
    let (result, post) = execute(&live, &block);
    let receipt = receipt(&result);
    assert!(receipt.success);
    assert_eq!(receipt.logs[1].topics[2], id);
    // Half the stake supports it: open in the fork slot, not yet enacted.
    let count_view = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(b"forkProposalCount()", None),
    );
    assert_eq!(count_view.output, U256::from(1).to_be_bytes::<32>());
    let proposal = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(b"forkProposalAt(uint256)", Some(U256::ZERO)),
    );
    assert_eq!(proposal.output[32..64], id);
    assert_eq!(proposal.output[96..128], U256::from(3).to_be_bytes::<32>());
    assert_eq!(
        proposal.output[160..192],
        U256::from(count).to_be_bytes::<32>()
    );
    let scheduled = simulate_system(
        &post,
        addresses::GOVERNANCE,
        system_call(b"scheduledFork()", None),
    );
    assert_eq!(scheduled.output, vec![0; 3 * 32]);
}

#[test]
fn withdrawal_status_reports_maturity_and_account_wide_sanction_hold() {
    let mut live = with_validator(genesis(Vec::new()), sender(), 100);
    let credentials = state::consensus_address(sender());
    live.insert(
        &neutrin0_runtime_system::withdrawal_key(&credentials),
        borsh::to_vec(&neutrin0_runtime_system::WithdrawalQueue {
            entries: vec![
                neutrin0_runtime_system::Withdrawal {
                    amount: 25,
                    mature_at_height: 0,
                },
                neutrin0_runtime_system::Withdrawal {
                    amount: 50,
                    mature_at_height: 7,
                },
            ],
        })
        .unwrap(),
    );
    live.insert(
        neutrin0_runtime_system::accountability::QUEUE_KEY,
        borsh::to_vec(&vec![
            neutrin0_runtime_system::accountability::PendingSanction {
                sanction: neutrin0_consensus_types::runtime::Sanction {
                    offence_id: [33; 32],
                    offender: neutrin0_primitives::Validator {
                        pubkey: [42; 48],
                        withdrawal_credentials: credentials,
                        effective_stake: 100,
                        activation_epoch: 0,
                        exit_epoch: u64::MAX,
                    },
                    kind: neutrin0_consensus_types::evidence::SanctionKind::Slash,
                },
                amount: 100,
                reporter: None,
                reporter_reward_bps: 0,
            },
        ])
        .unwrap(),
    );
    let result = simulate_system(
        &live,
        addresses::STAKING,
        system_call(
            b"withdrawalStatus(address)",
            Some(U256::from_be_bytes(credentials)),
        ),
    );
    assert!(result.success);
    let expected: Vec<u8> = [75_u64, 25, 1, 7]
        .into_iter()
        .flat_map(|word| U256::from(word).to_be_bytes::<32>())
        .collect();
    assert_eq!(result.output, expected);
}

#[test]
fn malformed_witnessed_delegation_code_is_a_state_error_instead_of_a_panic() {
    use revm::Database;
    let mut live = genesis(Vec::new());
    let raw = vec![0xef, 0x01, 0x00];
    let hash = keccak256(&raw);
    live.insert(&state::code_key(hash), raw);
    let mut trace = TracingState::new(&live);
    let mut db = state::StateDb::new(&mut trace, 0);
    assert_eq!(
        db.code_by_hash(hash),
        Err(state::StateError("malformed Ethereum delegation bytecode"))
    );
}

#[test]
fn mandatory_fifo_deducts_unbonding_pays_reporter_and_burns_the_escrow_remainder() {
    let mut live = with_validator(genesis(Vec::new()), sender(), 100);
    let credentials = state::consensus_address(sender());
    let reporter = Address::from([4; 20]);
    live.insert(
        &neutrin0_runtime_system::withdrawal_key(&credentials),
        borsh::to_vec(&neutrin0_runtime_system::WithdrawalQueue {
            entries: vec![neutrin0_runtime_system::Withdrawal {
                amount: 50,
                mature_at_height: 7,
            }],
        })
        .unwrap(),
    );
    let mut escrow = account(&live, addresses::ESCROW);
    escrow.balance = U256::from(150).to_be_bytes();
    live.insert(
        &state::account_key(addresses::ESCROW),
        borsh::to_vec(&escrow).unwrap(),
    );
    let pending = neutrin0_runtime_system::accountability::PendingSanction {
        sanction: neutrin0_consensus_types::runtime::Sanction {
            offence_id: [33; 32],
            offender: neutrin0_primitives::Validator {
                pubkey: [42; 48],
                withdrawal_credentials: credentials,
                effective_stake: 100,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
            },
            kind: neutrin0_consensus_types::evidence::SanctionKind::Slash,
        },
        amount: u128::MAX,
        reporter: Some(state::consensus_address(reporter)),
        reporter_reward_bps: 1_000,
    };
    live.insert(
        &neutrin0_runtime_system::accountability::slashed_key(&pending.sanction.offender.pubkey),
        vec![0],
    );
    live.insert(
        neutrin0_runtime_system::accountability::QUEUE_KEY,
        borsh::to_vec(&vec![pending]).unwrap(),
    );
    let (result, post) = execute(&live, &input(Vec::new()));
    assert_eq!(result.output.accountability.executed.len(), 1);
    assert_eq!(account(&post, addresses::ESCROW).balance, [0; 32]);
    assert_eq!(
        account(&post, reporter).balance,
        U256::from(15).to_be_bytes::<32>()
    );
    assert!(
        post.get(&neutrin0_runtime_system::withdrawal_key(&credentials))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        post.get(&neutrin0_runtime_system::accountability::slashed_key(
            &[42; 48]
        ))
        .unwrap(),
        Some(vec![1])
    );
    let totals = neutrin0_runtime_system::accountability::settlement::load_totals(
        &mut TracingState::new(&post),
    );
    assert_eq!(totals.slash.deducted.value, 150);
    assert_eq!(totals.slash.rewarded.value, 15);
    assert_eq!(totals.slash.burned.value, 135);
    assert_eq!(totals.slash.executed.value, 1);
}

#[test]
fn malformed_dynamic_system_offsets_revert_without_invalidating_the_block() {
    let live = genesis(Vec::new());
    let malformed = system_call(b"proposePolicy(bytes)", Some(U256::from(usize::MAX - 31)));
    let (result, post) = execute(
        &live,
        &input(vec![signed(
            0,
            TxKind::Call(addresses::GOVERNANCE),
            0,
            malformed,
            200_000,
        )]),
    );
    assert!(!receipt(&result).success);
    assert_eq!(account(&post, sender()).nonce, 1);
    assert!(
        post.get(neutrin0_runtime_system::governance::UPGRADE_PROPOSALS_KEY)
            .unwrap()
            .is_none()
    );
}

#[test]
fn runtime_gas_estimation_is_read_only_and_preserves_initial_revert_bytes() {
    use neutrin0_runtime_abi::{QueryRequest, ethereum::CallRequest};
    let contract = Address::from([5; 20]);
    let live = genesis(vec![GenesisAccount {
        address: contract.into_array(),
        balance: [0; 32],
        nonce: 1,
        code: vec![0x60, 0xab, 0x5f, 0x53, 0x60, 1, 0x5f, 0xfd],
        storage: Vec::new(),
    }]);
    let mut call = CallRequest {
        from: sender().into_array(),
        to: Some(Address::from([4; 20]).into_array()),
        value: [0; 32],
        data: Vec::new(),
        gas_limit: 100_000,
        fee_cap: None,
        tip_cap: None,
        access_list: Vec::new(),
        transaction_type: None,
        authorization_list: Vec::new(),
    };
    let mut trace = TracingState::new(&live);
    let estimate = |call: &CallRequest, state: &mut TracingState<'_>| {
        let response = crate::query(
            &QueryRequest {
                method: "evm:estimate_gas".into(),
                args: borsh::to_vec(call).unwrap(),
            },
            state,
        );
        assert!(response.is_ok(), "{response:?}");
        borsh::from_slice::<(crate::query::CallResult, u64)>(&response.payload).unwrap()
    };
    let (result, allowance) = estimate(&call, &mut trace);
    assert!(result.success);
    assert_eq!(result.gas_used, 21_000);
    assert_eq!(allowance, 21_000);
    assert_eq!(trace.post_state_root(), live.state_root());
    call.to = Some(contract.into_array());
    let (result, allowance) = estimate(&call, &mut trace);
    assert!(result.reverted);
    assert_eq!(result.output, vec![0xab]);
    assert_eq!(allowance, 0);
    assert_eq!(trace.post_state_root(), live.state_root());
}

#[test]
fn u256_funding_cannot_overflow_active_and_unclaimed_collateral_together() {
    let balance = U256::from(u128::MAX) + U256::from(1_000_000_000_u64);
    let mut live = with_validator(genesis_with_balance(Vec::new(), balance), sender(), 100);
    let credentials = state::consensus_address(sender());
    live.insert(
        &neutrin0_runtime_system::withdrawal_key(&credentials),
        borsh::to_vec(&neutrin0_runtime_system::WithdrawalQueue {
            entries: vec![neutrin0_runtime_system::Withdrawal {
                amount: u128::MAX - 100,
                mature_at_height: 7,
            }],
        })
        .unwrap(),
    );
    let mut escrow = account(&live, addresses::ESCROW);
    escrow.balance = U256::from(u128::MAX).to_be_bytes();
    live.insert(
        &state::account_key(addresses::ESCROW),
        borsh::to_vec(&escrow).unwrap(),
    );
    let block = input(vec![
        signed(
            0,
            TxKind::Call(addresses::STAKING),
            0,
            system_call(b"stake(uint256)", Some(U256::from(1))),
            300_000,
        ),
        signed(
            1,
            TxKind::Call(Address::from([4; 20])),
            1,
            Vec::new(),
            21_000,
        ),
    ]);
    let (result, post) = execute(&live, &block);
    let statuses: Vec<bool> = result
        .artifacts
        .receipts
        .iter()
        .filter_map(
            |bytes| match borsh::from_slice::<ExecutionReceipt>(bytes).unwrap() {
                ExecutionReceipt::Ethereum(receipt) => Some(receipt.success),
                ExecutionReceipt::System(_) => None,
            },
        )
        .collect();
    assert_eq!(statuses, vec![false, true]);
    assert_eq!(account(&post, sender()).nonce, 2);
    assert_eq!(account(&post, addresses::ESCROW), escrow);
    assert_eq!(
        post.get(&neutrin0_runtime_system::validator_key(&credentials))
            .unwrap(),
        live.get(&neutrin0_runtime_system::validator_key(&credentials))
            .unwrap()
    );
}
