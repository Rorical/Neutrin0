//! Mempool admission + gas accounting end-to-end coverage.
//!
//! Exercises the WASM `_neutrin0_validate_tx` path through
//! [`ChainBackend::submit_transaction`], then drives the producer's
//! drain → execute → `header.gas_used` loop to confirm the runtime's
//! gas figure flows into the consensus header (and from there into
//! the SP1 proof's public inputs).

use std::sync::Arc;

use alloy_primitives::Address;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_mempool::InsertError;
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, fixed_u128_from_integer,
};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
#[path = "support/evm.rs"]
pub mod evm;

const CHAIN_ID: u64 = 99;
/// Gas a plain EIP-1559 transfer consumes.
const TRANSFER_GAS: u64 = 21_000;

/// Encoded transfer of `amount` wei from the development account `seed`.
fn signed_transfer(seed: u8, to: Address, amount: u128, nonce: u64) -> Vec<u8> {
    evm::transfer(seed, nonce, to, amount, CHAIN_ID)
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0xA1; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xA1),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

/// Build a chain spec whose genesis funds `alice` with `balance` wei, so the
/// integration test can submit a valid transfer immediately at slot 1.
fn seeded_chain_spec(alice: Address, balance: u128) -> (ChainSpec, neutrin0_trie::Trie) {
    let vs_root = neutrin0_consensus_engine::validator_set_root(&validators());
    let genesis_block_hash = [0xCC; 32];
    let proof = ProofParams::default();
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    let mut spec = ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"mempool-admission".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: neutrin0_runtime_host::package::embedded_chunk_program()
            .expect("embedded chunk Guest"),
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0xAB; 32],
        genesis_state_root: neutrin0_primitives::ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    let accounts = vec![neutrin0_runtime_abi::ethereum::GenesisAccount {
        address: alice.into_array(),
        balance: alloy_primitives::U256::from(balance).to_be_bytes(),
        nonce: 0,
        code: Vec::new(),
        storage: Vec::new(),
    }];
    let trie = evm::seal_genesis(&mut spec, accounts);
    (spec, trie)
}

fn seeded_backend(
    alice: Address,
    balance: u128,
) -> Arc<ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>> {
    let (spec, trie) = seeded_chain_spec(alice, balance);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.install_genesis_state(trie).expect("genesis state");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::embedded().expect("wasm runtime"));
    backend
}

#[tokio::test(flavor = "multi_thread")]
async fn gossip_distinguishes_invalid_bytes_from_local_admission_limits() {
    use neutrin0_sync::{SyncBackend, SyncBackendError};
    let address = evm::address_of(1);
    let backend = tokio::task::spawn_blocking(move || seeded_backend(address, evm::FUNDS))
        .await
        .unwrap();
    let runtime = neutrin0_runtime_host::embedded_runtime_code_hash();
    assert!(matches!(
        SyncBackend::submit_transaction_in_runtime(backend.as_ref(), [99; 32], vec![255; 3]).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        SyncBackend::submit_transaction_in_runtime(backend.as_ref(), runtime, vec![255; 3]).await,
        Err(SyncBackendError::Rejected(_))
    ));
    let expensive = signed_transfer(1, Address::from([2; 20]), 2 * evm::FUNDS, 0);
    assert!(matches!(
        SyncBackend::submit_transaction_in_runtime(backend.as_ref(), runtime, expensive).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    let valid = signed_transfer(1, Address::from([2; 20]), 1, 0);
    assert!(
        SyncBackend::submit_transaction_in_runtime(backend.as_ref(), runtime, valid.clone())
            .await
            .is_ok()
    );
    assert!(matches!(
        SyncBackend::submit_transaction_in_runtime(backend.as_ref(), runtime, valid).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
}

#[test]
fn submit_transaction_rejects_malformed_payload() {
    let backend = seeded_backend(evm::address_of(1), 100);
    // Random bytes that are not an encoded transaction envelope.
    let err = backend
        .submit_transaction(vec![0xFF, 0xFF, 0xFF])
        .expect_err("malformed bytes must be rejected");
    assert_eq!(err, InsertError::RejectedByValidator);
    assert_eq!(backend.mempool_len(), 0);
}

#[test]
fn oversized_bodies_and_admitted_duplicates_do_not_execute_wasm_again() {
    let backend = seeded_backend(evm::address_of(1), evm::FUNDS);
    let bytes = signed_transfer(1, Address::from([2; 20]), 1, 0);
    backend.submit_transaction(bytes.clone()).unwrap();
    let mut before = String::new();
    backend
        .metrics()
        .execution
        .validation
        .render(&mut before, "validation", "Runtime admission");
    for _ in 0..16 {
        assert_eq!(
            backend.submit_transaction(bytes.clone()),
            Err(InsertError::Duplicate)
        );
    }
    assert_eq!(
        backend.submit_transaction(vec![0; 256 * 1024 + 1]),
        Err(InsertError::TooLarge)
    );
    let mut after = String::new();
    backend
        .metrics()
        .execution
        .validation
        .render(&mut after, "validation", "Runtime admission");
    assert_eq!(after, before);
}

#[tokio::test]
async fn rpc_submission_gossips_only_admitted_transactions_and_serves_content_hashes() {
    use neutrin0_network::{Topic, service::NetworkCommand};
    use neutrin0_rpc::RpcBackend;
    use neutrin0_sync::SyncBackend;
    let backend = seeded_backend(evm::address_of(55), evm::FUNDS);
    let (publisher, mut publications) = tokio::sync::mpsc::channel(4);
    backend.set_network_publisher(publisher);
    let bytes = signed_transfer(55, Address::from([9; 20]), 30, 0);
    RpcBackend::submit_transaction(backend.as_ref(), bytes.clone())
        .await
        .unwrap();
    let NetworkCommand::Publish { topic, data } = publications.try_recv().unwrap() else {
        panic!("RPC admission must publish transaction bytes");
    };
    assert_eq!(topic, Topic::Transactions);
    let announcement: neutrin0_network::rpc::TransactionAnnouncement =
        borsh::from_slice(&data).unwrap();
    assert_eq!(
        announcement.runtime,
        neutrin0_runtime_host::embedded_runtime_code_hash()
    );
    assert_eq!(announcement.transaction.as_slice(), bytes);
    assert!(
        RpcBackend::submit_transaction(backend.as_ref(), vec![0xff])
            .await
            .is_err()
    );
    assert!(
        RpcBackend::submit_transaction(backend.as_ref(), bytes.clone())
            .await
            .is_err()
    );
    assert!(publications.try_recv().is_err());
    let hash = neutrin0_primitives::blake3_256(&bytes);
    assert_eq!(
        SyncBackend::transaction_inventory(backend.as_ref(), None).await,
        vec![hash]
    );
    assert_eq!(
        SyncBackend::transaction_inventory(backend.as_ref(), Some(hash)).await,
        Vec::<[u8; 32]>::new()
    );
    assert_eq!(
        SyncBackend::pending_transactions(backend.as_ref(), &[hash, [0; 32]]).await,
        vec![bytes]
    );
    assert_eq!(
        SyncBackend::missing_transactions(backend.as_ref(), &[hash, [0; 32]]).await,
        vec![[0; 32]]
    );
}

/// Two real TCP network/sync stacks; no block production is needed to repair pools.
struct TransactionPeer {
    commands: tokio::sync::mpsc::Sender<neutrin0_network::service::NetworkCommand>,
    address: neutrin0_network::libp2p::Multiaddr,
    peer_id: neutrin0_network::PeerId,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for TransactionPeer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn transaction_peer(
    backend: Arc<ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>>,
) -> TransactionPeer {
    use neutrin0_network::{
        Topic,
        service::{NetworkCommand, NetworkEvent, NetworkService},
    };
    use neutrin0_sync::{SyncBackend, SyncDriver, SyncDriverConfig};
    let (commands, commands_rx) = tokio::sync::mpsc::channel(64);
    let (events_tx, mut events) = tokio::sync::mpsc::channel(64);
    let mut service = NetworkService::new(
        neutrin0_network::libp2p::identity::Keypair::generate_ed25519(),
        commands_rx,
        events_tx,
    )
    .unwrap();
    service.require_chain(SyncBackend::local_status(backend.as_ref()).await.unwrap());
    let peer_id = *service.local_peer_id();
    service
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let network = tokio::spawn(async move {
        Box::pin(service.run()).await.unwrap();
    });
    commands
        .send(NetworkCommand::Subscribe(Topic::Transactions))
        .await
        .unwrap();
    let address = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(NetworkEvent::NewListenAddr(address)) = events.recv().await {
                break address;
            }
        }
    })
    .await
    .unwrap();
    backend.set_network_publisher(commands.clone());
    let progress = SyncBackend::local_progress(backend.as_ref()).await.unwrap();
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        backend,
        progress,
        commands.clone(),
        events,
    );
    let sync = tokio::spawn(async move {
        driver.run().await;
    });
    TransactionPeer {
        commands,
        address,
        peer_id,
        tasks: vec![network, sync],
    }
}

async fn transaction_attacker(
    victim: &TransactionPeer,
    status: neutrin0_network::rpc::Status,
) -> (
    TransactionPeer,
    tokio::sync::mpsc::Receiver<neutrin0_network::service::NetworkEvent>,
) {
    use neutrin0_network::{
        Topic,
        service::{NetworkCommand, NetworkEvent, NetworkService},
    };
    let (commands, commands_rx) = tokio::sync::mpsc::channel(64);
    let (events_tx, mut events) = tokio::sync::mpsc::channel(64);
    let mut service = NetworkService::new(
        neutrin0_network::libp2p::identity::Keypair::generate_ed25519(),
        commands_rx,
        events_tx,
    )
    .unwrap();
    service.require_chain(status);
    let peer_id = *service.local_peer_id();
    let network = tokio::spawn(async move {
        Box::pin(service.run()).await.unwrap();
    });
    commands
        .send(NetworkCommand::Subscribe(Topic::Transactions))
        .await
        .unwrap();
    commands
        .send(NetworkCommand::Dial(victim.address.clone()))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop { if matches!(events.recv().await, Some(NetworkEvent::PeerConnected(peer)) if peer == victim.peer_id) { break; } }
    }).await.unwrap();
    (
        TransactionPeer {
            commands,
            address: victim.address.clone(),
            peer_id,
            tasks: vec![network],
        },
        events,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_transaction_peer_is_graylisted_while_honest_tcp_propagation_continues() {
    use neutrin0_network::{Topic, service::NetworkCommand};
    use neutrin0_sync::SyncBackend;
    let address = evm::address_of(57);
    let (first, second) = tokio::task::spawn_blocking(move || {
        (
            seeded_backend(address, evm::FUNDS),
            seeded_backend(address, evm::FUNDS),
        )
    })
    .await
    .unwrap();
    let a = transaction_peer(first.clone()).await;
    let b = transaction_peer(second.clone()).await;
    b.commands
        .send(NetworkCommand::Dial(a.address.clone()))
        .await
        .unwrap();
    let (attacker, _attacker_events) =
        transaction_attacker(&a, SyncBackend::local_status(first.as_ref()).await.unwrap()).await;
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    attacker
        .commands
        .send(NetworkCommand::Publish {
            topic: Topic::Transactions,
            data: borsh::to_vec(&neutrin0_network::rpc::TransactionAnnouncement {
                runtime: neutrin0_runtime_host::embedded_runtime_code_hash(),
                transaction: neutrin0_primitives::BoundedBytes::new(vec![255; 128]).unwrap(),
            })
            .unwrap(),
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let (reply, received) = tokio::sync::oneshot::channel();
            a.commands
                .send(NetworkCommand::QueryPeerScores { response_tx: reply })
                .await
                .unwrap();
            let scores = received.await.unwrap();
            if scores
                .iter()
                .any(|(peer, score)| *peer == attacker.peer_id && *score <= -80.0)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(first.mempool_len(), 0);
    let bytes = signed_transfer(57, Address::from([8; 20]), 30, 0);
    let hash = neutrin0_rpc::RpcBackend::submit_transaction(first.as_ref(), bytes.clone())
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while SyncBackend::pending_transactions(second.as_ref(), &[hash]).await
            != vec![bytes.clone()]
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_transaction_recovers_over_tcp_when_submitted_before_peers_connect() {
    use neutrin0_network::service::NetworkCommand;
    use neutrin0_rpc::RpcBackend;
    let address = evm::address_of(56);
    let (first, second) = tokio::task::spawn_blocking(move || {
        (
            seeded_backend(address, evm::FUNDS),
            seeded_backend(address, evm::FUNDS),
        )
    })
    .await
    .unwrap();
    let a = transaction_peer(Arc::clone(&first)).await;
    let b = transaction_peer(Arc::clone(&second)).await;
    let bytes = signed_transfer(56, Address::from([8; 20]), 30, 0);
    // Initial gossip has no recipient. Only automatic pending-pool discovery
    // can recover this transaction; the client submits once to one backend.
    RpcBackend::submit_transaction(first.as_ref(), bytes)
        .await
        .unwrap();
    assert_eq!(second.mempool_len(), 0);
    a.commands
        .send(NetworkCommand::Dial(b.address.clone()))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while second.mempool_len() != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("peer must recover missed gossip automatically");
    let hashes = neutrin0_sync::SyncBackend::transaction_inventory(first.as_ref(), None).await;
    assert_eq!(
        neutrin0_sync::SyncBackend::transaction_inventory(second.as_ref(), None).await,
        hashes
    );
    assert_eq!(
        neutrin0_sync::SyncBackend::pending_transactions(first.as_ref(), &hashes).await,
        neutrin0_sync::SyncBackend::pending_transactions(second.as_ref(), &hashes).await
    );
}

#[test]
fn submit_transaction_rejects_proof_admission() {
    let backend = seeded_backend(evm::address_of(2), 100);
    // Evidence submissions require the verified admission path; ordinary admission refuses
    // them with the Unauthorized rejection code so a malicious peer
    // cannot inject one through gossip or RPC.
    let submission = neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(Box::new(
        neutrin0_consensus_types::evidence::EvidenceSubmission {
            statement: neutrin0_consensus_types::evidence::EvidenceStatement {
                chain_id: 7,
                chain_spec_hash: [0; 32],
                block_guest_vk_digest: [0; 8],
                context: neutrin0_consensus_types::evidence::EvidenceContext {
                    chunk_id: 0,
                    chunk_hash: [0; 32],
                    end_height: 1,
                    validators_root: [0; 32],
                    seed: [0; 32],
                    source_block_guest_vk_digest: [0; 8],
                    source_runtime_code_hash: [0; 32],
                    start_boundary: [0; 32],
                },
                offender: validators()[0].clone(),
                kind: neutrin0_consensus_types::evidence::SanctionKind::Slash,
                offence_id: [0; 32],
                facts_commitment: [0; 32],
                reporter: None,
            },
            history: neutrin0_consensus_types::history::HistoryPath {
                index: 0,
                count: 1,
                siblings: vec![[0; 32]; 64],
            },
        },
    ));
    let bytes = borsh::to_vec(&submission).expect("encode tx");
    let err = backend
        .submit_transaction(bytes)
        .expect_err("Evidence submission requires proof admission");
    assert_eq!(err, InsertError::RejectedByValidator);
    assert_eq!(backend.mempool_len(), 0);
}

#[test]
fn submit_transaction_rejects_insufficient_balance() {
    let backend = seeded_backend(evm::address_of(3), 10); // only 10 wei
    // More than the balance, before any gas.
    let bytes = signed_transfer(3, Address::from([0xAB; 20]), 50, 0);
    let err = backend
        .submit_transaction(bytes)
        .expect_err("insufficient balance must be rejected");
    assert_eq!(err, InsertError::RejectedByValidator);
    assert_eq!(backend.mempool_len(), 0);
}

#[test]
fn submit_transaction_admits_valid_transfer_and_block_charges_gas() {
    let alice_addr = evm::address_of(4);
    let bob_addr = Address::from([0xBB; 20]);
    // Covers the transfer and its gas.
    let backend = seeded_backend(alice_addr, evm::FUNDS);

    // Admit a valid transfer.
    let bytes = signed_transfer(4, bob_addr, 30, 0);
    backend
        .submit_transaction(bytes.clone())
        .expect("valid transfer admits");
    assert_eq!(
        backend.mempool_len(),
        1,
        "admitted tx must land in the mempool",
    );

    // Duplicate admission is rejected at the pool layer, not the
    // runtime layer.
    let err = backend
        .submit_transaction(bytes)
        .expect_err("duplicate must be rejected");
    assert_eq!(err, InsertError::Duplicate);

    // Produce slot 1: the mempool drains and the tx lands in the body.
    let outcome = backend
        .try_produce_block(1, &proposer_key())
        .expect("try_produce_block")
        .expect("validator is eligible");
    assert_eq!(outcome.block.header.height, 1);
    assert_eq!(
        outcome.block.body.transactions.len(),
        1,
        "the admitted transfer must be drained into the body",
    );
    assert_eq!(
        outcome.block.header.gas_used, TRANSFER_GAS,
        "header.gas_used must reflect the runtime's reported consumption",
    );
    assert_eq!(
        outcome.gas_used, TRANSFER_GAS,
        "production outcome's gas_used must match",
    );
    assert!(
        outcome.block.header.gas_used <= outcome.block.header.gas_limit,
        "gas_used must respect gas_limit",
    );
    assert_eq!(
        backend.mempool_len(),
        0,
        "mempool must drain after successful production",
    );

    // Prove the block and ensure the SP1 path is happy. The
    // `Sp1ProofSystem::prove_block` adapter cross-checks
    // `RuntimeBlockOutput.gas_used` against
    // `BlockProofPublicInputs.gas_used`, so a successful prove
    // confirms the gas figure was propagated end-to-end.
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block on the freshly produced block");
    assert_eq!(
        proven.public_inputs.gas_used, TRANSFER_GAS,
        "block proof public inputs commit to the same gas_used",
    );
    assert_eq!(
        proven.public_inputs.gas_limit, outcome.block.header.gas_limit,
        "block proof public inputs commit to the header's gas_limit",
    );
}
