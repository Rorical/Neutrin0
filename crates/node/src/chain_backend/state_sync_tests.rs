//! State download regression tests without accepting synthetic proof receipts.

use super::{ChainBackend, state_sync::MAX_ENTRY_BYTES};
use neutrin0_consensus_engine::{Engine, ProposerKey, validator_set::validator_set_root};
use neutrin0_consensus_types::bootstrap::{StateItem, StateItemKind};
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH,
};
use neutrin0_proof_system::MockProofSystem;
use neutrin0_storage::{Column, Database, MemoryDatabase};
use neutrin0_trie::{Hasher, Poseidon2Hasher, Trie};

type Backend = ChainBackend<MemoryDatabase, MockProofSystem>;

pub(super) fn spec() -> ChainSpec {
    let validators = vec![Validator {
        pubkey: *ProposerKey::from_ikm(&[6; 32], 0)
            .unwrap()
            .public_key_bytes(),
        withdrawal_credentials: neutrin0_primitives::runtime_account([7; 20]),
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
        name: BoundedBytes::new(b"state-download".to_vec()).unwrap(),
        chain_id: 41,
        genesis_time: 0,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [1; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [2; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash: [4; 32],
        genesis_validator_set_root: validator_set_root(&validators),
        consensus: ConsensusParams::default(),
        proof: ProofParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}
fn backend() -> Backend {
    ChainBackend::new(
        Engine::genesis(spec(), MemoryDatabase::new()).unwrap(),
        MockProofSystem::new(),
    )
}
fn source(value: &[u8]) -> (Backend, neutrin0_primitives::Hash) {
    source_of(&[(b"large", value)])
}
fn source_of(entries: &[(&[u8], &[u8])]) -> (Backend, neutrin0_primitives::Hash) {
    let server = backend();
    let mut state: Trie = Trie::new();
    for (key, value) in entries {
        state.insert(key, value.to_vec()).unwrap();
    }
    let root = state.root();
    server.with_engine_mut(|engine| {
        for (hash, bytes) in state.node_entries() {
            engine
                .store_mut()
                .db_mut()
                .put(Column::TrieNodes, &hash, bytes)
                .unwrap();
        }
        for (hash, bytes) in state.value_entries() {
            engine
                .store_mut()
                .db_mut()
                .put(Column::StateValues, &hash, bytes)
                .unwrap();
        }
    });
    (server, root)
}
fn receive(
    server: &Backend,
    client: &Backend,
    root: neutrin0_primitives::Hash,
) -> neutrin0_sync::StateProgress {
    let items = client.state_download_items(root).unwrap();
    let response = server.p2p_state_nodes(root, &items).unwrap();
    client
        .receive_state_entries(root, &items, &response.entries)
        .unwrap()
}

#[test]
fn runtime_program_fragments_resume_separately_and_reject_forged_bytes() {
    use neutrin0_consensus_types::bootstrap::{MAX_STATE_FRAGMENT_BYTES, StateEntry};
    let mut bytes = vec![7; MAX_STATE_FRAGMENT_BYTES + 10];
    bytes[..4].copy_from_slice(b"\0asm");
    let hash = neutrin0_primitives::blake3_256(&bytes);
    let item = StateItem::runtime(hash);
    let client = backend();
    client
        .require_bootstrap_programs(ZERO_HASH, &[item])
        .unwrap();
    let first = StateEntry {
        item,
        total_len: bytes.len() as u64,
        bytes: BoundedBytes::new(bytes[..MAX_STATE_FRAGMENT_BYTES].to_vec()).unwrap(),
    };
    let progress = client
        .receive_state_entries(ZERO_HASH, &[item], &[first])
        .unwrap();
    assert!(!progress.root_complete);
    assert_eq!(
        progress.next_items[0].offset,
        MAX_STATE_FRAGMENT_BYTES as u64
    );
    let db = client.with_engine(|engine| engine.store().db().clone());
    let resumed = ChainBackend::new(Engine::open(spec(), db).unwrap(), MockProofSystem);
    let next = progress.next_items[0];
    let forged = StateEntry {
        item: next,
        total_len: bytes.len() as u64,
        bytes: BoundedBytes::new(vec![8; 10]).unwrap(),
    };
    assert!(matches!(
        resumed.receive_state_entries(ZERO_HASH, &[next], &[forged]),
        Err(neutrin0_sync::SyncBackendError::Rejected(_))
    ));
    assert_eq!(resumed.state_download_items(ZERO_HASH).unwrap(), vec![item]);
    let complete = StateEntry {
        item,
        total_len: 4,
        bytes: BoundedBytes::new(vec![7; 4]).unwrap(),
    };
    assert!(
        resumed
            .receive_state_entries(ZERO_HASH, &[item], &[complete])
            .is_err()
    );
    assert_eq!(resumed.with_engine(Engine::head_state_root), ZERO_HASH);
    assert_eq!(resumed.downloaded_program(ZERO_HASH, item).unwrap(), None);
    let first = StateEntry {
        item,
        total_len: bytes.len() as u64,
        bytes: BoundedBytes::new(bytes[..MAX_STATE_FRAGMENT_BYTES].to_vec()).unwrap(),
    };
    resumed
        .receive_state_entries(ZERO_HASH, &[item], &[first])
        .unwrap();
    let last = StateEntry {
        item: next,
        total_len: bytes.len() as u64,
        bytes: BoundedBytes::new(bytes[MAX_STATE_FRAGMENT_BYTES..].to_vec()).unwrap(),
    };
    assert!(
        resumed
            .receive_state_entries(ZERO_HASH, &[next], &[last])
            .unwrap()
            .root_complete
    );
    assert_eq!(
        resumed.downloaded_program(ZERO_HASH, item).unwrap(),
        Some(bytes)
    );
    assert_eq!(resumed.with_engine(Engine::head_state_root), ZERO_HASH);
}

#[test]
fn guest_program_download_has_the_program_bound_and_never_populates_state_values() {
    use neutrin0_consensus_types::bootstrap::StateEntry;
    let client = backend();
    let item = StateItem::guest([1; 8]);
    client
        .require_bootstrap_programs(ZERO_HASH, &[item])
        .unwrap();
    let oversized = StateEntry {
        item,
        total_len: u64::from(neutrin0_consensus_types::MAX_PROGRAM_BYTES) + 1,
        bytes: BoundedBytes::new(vec![0x7f, b'E', b'L', b'F']).unwrap(),
    };
    assert!(matches!(
        client.receive_state_entries(ZERO_HASH, &[item], &[oversized]),
        Err(neutrin0_sync::SyncBackendError::Rejected(_))
    ));
    assert_eq!(client.state_download_items(ZERO_HASH).unwrap(), vec![item]);
    assert_eq!(
        client.with_engine(|engine| engine
            .store()
            .db()
            .iter_column(Column::StateValues)
            .unwrap()),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
}

#[tokio::test]
async fn a_downloaded_genesis_guest_with_other_content_is_reset_before_any_setup() {
    use neutrin0_consensus_types::bootstrap::StateEntry;
    let mut pinned = spec();
    pinned.genesis_artifacts.fact = [9; 32];
    let client = ChainBackend::new(
        Engine::genesis(pinned, MemoryDatabase::new()).unwrap(),
        MockProofSystem::new(),
    );
    let item = StateItem::guest([1; 8]);
    client
        .require_bootstrap_programs(ZERO_HASH, &[item])
        .unwrap();
    let elf = vec![0x7f, b'E', b'L', b'F', 0];
    let entry = StateEntry {
        item,
        total_len: elf.len() as u64,
        bytes: BoundedBytes::new(elf).unwrap(),
    };
    client
        .receive_state_entries(ZERO_HASH, &[item], &[entry])
        .unwrap();
    assert!(matches!(
        client
            .authenticate_received_guests(ZERO_HASH, &[item])
            .await,
        Err(neutrin0_sync::SyncBackendError::Rejected(reason))
            if reason.contains("content hash mismatch")
    ));
    // The object is pending again, to be fetched from another provider.
    assert_eq!(client.state_download_items(ZERO_HASH).unwrap(), vec![item]);
}

#[test]
fn fragment_service_rejects_unknown_or_corrupt_roots_before_serving_retained_objects() {
    let (server, root) = source(b"authenticated value");
    let items = vec![StateItem::node(root)];
    assert!(matches!(
        server.p2p_state_nodes([9; 32], &items),
        Err(neutrin0_sync::SyncBackendError::NotAvailable(_))
    ));
    let response = server.p2p_state_nodes(root, &items).unwrap();
    assert_eq!(response.entries[0].item, items[0]);
    assert_eq!(
        Poseidon2Hasher::hash_node(response.entries[0].bytes.as_slice()),
        root
    );
    assert!(
        server
            .with_engine(|engine| engine.store().db().iter_column(Column::Meta).unwrap())
            .iter()
            .all(|(key, _)| !key.starts_with(b"state_snapshot_lease/"))
    );
    let client = backend();
    while !receive(&server, &client, root).root_complete {}
    assert_eq!(
        client
            .reconstructed_state(root)
            .unwrap()
            .get(b"large")
            .unwrap(),
        Some(b"authenticated value".to_vec())
    );
    server.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::TrieNodes, &root, &[255])
            .unwrap();
    });
    // The root is checked even when no object fragments were requested.
    assert!(matches!(
        server.p2p_state_nodes(root, &[]),
        Err(neutrin0_sync::SyncBackendError::Storage(_))
    ));
    let malformed_root = Poseidon2Hasher::hash_node(&[255]);
    server.with_engine_mut(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::TrieNodes, &malformed_root, &[255])
            .unwrap();
    });
    assert!(matches!(
        server.p2p_state_nodes(malformed_root, &[]),
        Err(neutrin0_sync::SyncBackendError::Storage(_))
    ));
}

#[test]
fn large_value_fragments_resume_after_restart_and_do_not_publish_partial_state() {
    let value = vec![5; 150_000];
    let (server, root) = source(&value);
    let client = backend();
    assert!(!receive(&server, &client, root).root_complete); // Root authenticates the value hash.
    let progress = receive(&server, &client, root);
    assert_eq!(progress.next_items[0].kind, StateItemKind::Value);
    assert_eq!(progress.next_items[0].offset, 65_536);
    let db = client.with_engine(|engine| engine.store().db().clone());
    assert_eq!(
        db.iter_column(Column::TrieNodes).unwrap(),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    let resumed = ChainBackend::new(Engine::open(spec(), db).unwrap(), MockProofSystem::new());
    assert_eq!(
        resumed.state_download_items(root).unwrap(),
        progress.next_items
    );
    while !receive(&server, &resumed, root).root_complete {}
    let state = resumed.reconstructed_state(root).unwrap();
    assert_eq!(state.get(b"large").unwrap(), Some(value));
    assert_eq!(resumed.with_engine(Engine::head_state_root), ZERO_HASH);
    resumed.clear_state_download(root).unwrap();
    assert!(
        resumed
            .with_engine(|engine| engine.store().db().iter_column(Column::Meta).unwrap())
            .iter()
            .all(|(key, _)| !key.starts_with(b"state_download"))
    );
}

#[test]
fn corrupt_final_fragment_restarts_only_that_object_from_zero() {
    let (server, root) = source(&vec![7; 80_000]);
    let client = backend();
    receive(&server, &client, root);
    receive(&server, &client, root);
    let items = client.state_download_items(root).unwrap();
    let mut entries = server
        .p2p_state_nodes(root, &items)
        .unwrap()
        .entries
        .to_vec();
    let mut corrupt = entries[0].bytes.as_slice().to_vec();
    corrupt[0] ^= 1;
    entries[0].bytes = BoundedBytes::new(corrupt).unwrap();
    assert!(
        client
            .receive_state_entries(root, &items, &entries)
            .is_err()
    );
    let restarted = client.state_download_items(root).unwrap();
    assert_eq!(restarted[0].offset, 0);
    while !receive(&server, &client, root).root_complete {}
    assert_eq!(
        client
            .reconstructed_state(root)
            .unwrap()
            .get(b"large")
            .unwrap(),
        Some(vec![7; 80_000])
    );
}

#[test]
fn a_restarted_partial_object_is_fetched_again_from_byte_zero() {
    let value = vec![6; 150_000];
    let (server, root) = source(&value);
    let client = backend();
    receive(&server, &client, root);
    let partial = receive(&server, &client, root).next_items;
    assert_eq!(partial[0].offset, 65_536);
    client.restart_state_fragments(&partial).unwrap();
    let restarted = client.state_download_items(root).unwrap();
    assert_eq!(restarted[0].offset, 0);
    while !receive(&server, &client, root).root_complete {}
    assert_eq!(
        client
            .reconstructed_state(root)
            .unwrap()
            .get(b"large")
            .unwrap(),
        Some(value)
    );
}

#[test]
fn unsolicited_fragment_and_giant_declared_length_cannot_change_progress() {
    let (server, root) = source(b"value");
    let client = backend();
    let items = vec![StateItem::node(root)];
    let mut entries = server
        .p2p_state_nodes(root, &items)
        .unwrap()
        .entries
        .to_vec();
    entries[0].item.hash = [9; 32];
    assert!(
        client
            .receive_state_entries(root, &items, &entries)
            .is_err()
    );
    assert_eq!(client.state_download_items(root).unwrap(), items);
    entries[0].item = items[0];
    entries[0].total_len = MAX_ENTRY_BYTES + 1;
    assert!(
        client
            .receive_state_entries(root, &items, &entries)
            .is_err()
    );
    assert_eq!(client.state_download_items(root).unwrap(), items);
}

#[test]
fn independent_execution_and_identity_roots_resume_without_overwriting_progress() {
    let execution = vec![5; 150_000];
    let bans = vec![1; 90_000];
    let (execution_server, execution_root) = source(&execution);
    let (bans_server, bans_root) = source(&bans);
    let client = backend();
    assert!(!receive(&execution_server, &client, execution_root).root_complete);
    let execution_progress = receive(&execution_server, &client, execution_root);
    assert!(!receive(&bans_server, &client, bans_root).root_complete);
    let bans_progress = receive(&bans_server, &client, bans_root);
    let db = client.with_engine(|engine| engine.store().db().clone());
    let resumed = ChainBackend::new(Engine::open(spec(), db).unwrap(), MockProofSystem::new());
    assert_eq!(
        resumed.state_download_items(execution_root).unwrap(),
        execution_progress.next_items
    );
    assert_eq!(
        resumed.state_download_items(bans_root).unwrap(),
        bans_progress.next_items
    );
    while !receive(&bans_server, &resumed, bans_root).root_complete {}
    assert_eq!(
        resumed
            .reconstructed_state(bans_root)
            .unwrap()
            .get(b"large")
            .unwrap(),
        Some(bans)
    );
    resumed.clear_state_download(bans_root).unwrap();
    assert_eq!(
        resumed.state_download_items(execution_root).unwrap(),
        execution_progress.next_items
    );
    while !receive(&execution_server, &resumed, execution_root).root_complete {}
    assert_eq!(
        resumed
            .reconstructed_state(execution_root)
            .unwrap()
            .get(b"large")
            .unwrap(),
        Some(execution)
    );
    assert_eq!(resumed.with_engine(Engine::head_state_root), ZERO_HASH);
    assert_eq!(resumed.with_engine(Engine::finalized_next_chunk_id), 0);
}

/// Staged object rows (`o`), by hash.
fn staged_objects(client: &Backend) -> Vec<neutrin0_primitives::Hash> {
    let prefix = b"state_download_entry/o";
    client.with_engine(|engine| {
        engine
            .store()
            .db()
            .iter_prefix(Column::Meta, prefix)
            .unwrap()
            .into_iter()
            .map(|(key, _)| key[prefix.len() + 1..].try_into().unwrap())
            .collect()
    })
}

#[test]
fn a_newer_root_reuses_what_the_root_it_replaces_staged() {
    let shared = vec![5; 150_000];
    let shared_hash = Poseidon2Hasher::hash_value(&shared);
    let (old_server, old_root) = source_of(&[(b"large", &shared), (b"small", b"one")]);
    let (new_server, new_root) = source_of(&[(b"large", &shared), (b"small", b"two")]);
    let client = backend();
    while !receive(&old_server, &client, old_root).root_complete {}
    client.abandon_state_download(old_root).unwrap();
    let mut fetched = Vec::new();
    loop {
        let items = client.state_download_items(new_root).unwrap();
        fetched.extend(items.iter().map(|item| item.hash));
        let response = new_server.p2p_state_nodes(new_root, &items).unwrap();
        if client
            .receive_state_entries(new_root, &items, &response.entries)
            .unwrap()
            .root_complete
        {
            break;
        }
    }
    // The shared value never crosses the network again.
    assert!(!fetched.contains(&shared_hash));
    assert!(fetched.contains(&new_root));
    assert_eq!(
        client
            .reconstructed_state(new_root)
            .unwrap()
            .get(b"large")
            .unwrap(),
        Some(shared)
    );
    // Sweeping drops only what the remaining root does not hold.
    let before = staged_objects(&client);
    client.sweep_unreferenced_objects().unwrap();
    let after = staged_objects(&client);
    assert!(after.len() < before.len());
    assert!(after.contains(&shared_hash) && !after.contains(&old_root));
    let state = client.reconstructed_state(new_root).unwrap();
    assert_eq!(state.get(b"small").unwrap(), Some(b"two".to_vec()));
}

#[test]
fn roots_waiting_for_one_object_share_its_staged_fragments() {
    let shared = vec![5; 150_000];
    let shared_hash = Poseidon2Hasher::hash_value(&shared);
    let (first_server, first_root) = source_of(&[(b"large", &shared), (b"small", b"one")]);
    let (second_server, second_root) = source_of(&[(b"large", &shared), (b"small", b"two")]);
    let client = backend();
    let staged = |items: &[StateItem]| {
        items
            .iter()
            .find(|item| item.hash == shared_hash)
            .map(|item| item.offset)
    };
    while staged(&client.state_download_items(first_root).unwrap()) != Some(65_536) {
        receive(&first_server, &client, first_root);
    }
    // The second root discovers the value at the first root's progress.
    while staged(&client.state_download_items(second_root).unwrap()).is_none() {
        receive(&second_server, &client, second_root);
    }
    assert_eq!(
        staged(&client.state_download_items(second_root).unwrap()),
        Some(65_536)
    );
    while !receive(&second_server, &client, second_root).root_complete {}
    // Completed through the second root, the value resolves locally for the first.
    assert_eq!(
        staged(&client.state_download_items(first_root).unwrap()),
        None
    );
    while !receive(&first_server, &client, first_root).root_complete {}
    for root in [first_root, second_root] {
        assert_eq!(
            client
                .reconstructed_state(root)
                .unwrap()
                .get(b"large")
                .unwrap(),
            Some(shared.clone())
        );
    }
}

#[test]
fn an_interrupted_install_finishes_before_its_staged_objects_go() {
    let entries: Vec<(Vec<u8>, Vec<u8>)> =
        (0_u8..8).map(|byte| (vec![byte], vec![byte; 40])).collect();
    let pairs: Vec<(&[u8], &[u8])> = entries
        .iter()
        .map(|(key, value)| (key.as_slice(), value.as_slice()))
        .collect();
    let (server, root) = source_of(&pairs);
    let client = backend();
    while !receive(&server, &client, root).root_complete {}
    // One slice, then a restart: the walk has written a node whose edges
    // below are not counted yet.
    let remote = server.with_engine(|engine| engine.store().state_at(root));
    assert!(
        !client
            .with_engine_mut(|engine| engine.store_mut().install_state_slice(&[root], &remote, 1))
            .unwrap()
    );
    let db = client.with_engine(|engine| engine.store().db().clone());
    let resumed = ChainBackend::new(Engine::open(spec(), db).unwrap(), MockProofSystem::new());
    // Dropping the download first finishes the walk from the staged objects.
    resumed.clear_state_download(root).unwrap();
    let installed = resumed.with_engine(|engine| engine.store().state_install().unwrap());
    assert_eq!(
        installed,
        Some(neutrin0_consensus_engine::store::StateInstall {
            roots: vec![root],
            finished: true
        })
    );
    assert_eq!(
        resumed.with_engine(|engine| engine.store().state_at(root).get(&[3]).unwrap()),
        Some(vec![3; 40])
    );
    // Released, it is collected entirely.
    resumed
        .with_engine_mut(|engine| engine.store_mut().release_state_install())
        .unwrap();
    while !resumed
        .with_engine_mut(|engine| engine.collect_state_slice(16))
        .unwrap()
    {}
    for column in [Column::TrieNodes, Column::StateValues, Column::StateRefs] {
        assert_eq!(
            resumed.with_engine(|engine| engine.store().db().iter_column(column).unwrap()),
            Vec::<(Vec<u8>, Vec<u8>)>::new()
        );
    }
}
