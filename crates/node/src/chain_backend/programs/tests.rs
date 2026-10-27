use super::*;
use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::bootstrap::{StateEntry, StateItem};
use neutrin0_primitives::BoundedBytes;
use neutrin0_proof_system::MockProofSystem;
use neutrin0_storage::MemoryDatabase;

fn backend() -> ChainBackend<MemoryDatabase, MockProofSystem> {
    ChainBackend::new(
        Engine::genesis(
            super::super::state_sync_tests::spec(),
            MemoryDatabase::new(),
        )
        .unwrap(),
        MockProofSystem::new(),
    )
}

fn start(backend: &ChainBackend<MemoryDatabase, MockProofSystem>, identity: ExpectedIdentity) {
    start_pinned(backend, identity, None);
}

fn start_pinned(
    backend: &ChainBackend<MemoryDatabase, MockProofSystem>,
    identity: ExpectedIdentity,
    content: Option<neutrin0_primitives::Hash>,
) {
    *backend.program_fetch.lock().unwrap() = Some(ProgramFetch {
        identity,
        content,
        total_len: None,
        bytes: Vec::new(),
        assembled: None,
        rejected: Arc::default(),
    });
}

fn fragment(item: StateItem, bytes: &[u8], total_len: u64) -> StateEntry {
    StateEntry {
        item,
        total_len,
        bytes: BoundedBytes::new(bytes.to_vec()).unwrap(),
    }
}

/// A program is fetched by identity in ordered fragments; fragments of
/// another offset or length are refused, and the bytes are indexed only
/// under the identity they reproduce.
#[test]
fn programs_are_fetched_by_identity_and_indexed_only_when_they_reproduce_it() {
    let mut bytes = b"\0asm".to_vec();
    bytes.resize(100_000, 7);
    let total = bytes.len() as u64;
    let (head, tail) =
        bytes.split_at(neutrin0_consensus_types::bootstrap::MAX_STATE_FRAGMENT_BYTES);
    let code_hash = neutrin0_primitives::blake3_256(&bytes);
    let identity = ExpectedIdentity::Runtime(code_hash);
    let requester = backend();
    start(&requester, identity);
    let first = requester.next_program_fetch().unwrap();
    assert_eq!(first, StateItem::runtime(code_hash));
    assert!(requester.absorb_fetched_fragment(&fragment(first, head, total)));
    let second = requester.next_program_fetch().unwrap();
    assert_eq!(second.offset, head.len() as u64);
    assert!(!requester.absorb_fetched_fragment(&fragment(first, head, total)));
    assert!(!requester.absorb_fetched_fragment(&fragment(second, tail, total + 1)));
    assert!(requester.absorb_fetched_fragment(&fragment(second, tail, total)));
    assert_eq!(
        requester.program_store().read_identity(identity),
        Some(bytes.clone())
    );
    assert!(requester.holds_program(identity));

    // Bytes answering another identity are assembled but never indexed.
    let other = ExpectedIdentity::Runtime([9; 32]);
    let misled = backend();
    start(&misled, other);
    let item = misled.next_program_fetch().unwrap();
    assert!(misled.absorb_fetched_fragment(&fragment(item, tail, tail.len() as u64)));
    assert!(misled.program_store().read_identity(other).is_none());
    assert!(!misled.holds_program(other));
    // Rejected bytes are dropped at once rather than held for the install
    // grace, so the next fetch starts over and the driver asks other
    // providers.
    let _ = misled.next_program_fetch();
    assert!(
        misled
            .program_fetch
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|fetch| fetch.assembled.is_none())
    );
}

/// Bytes whose content hash differs from the one the chain pins are refused
/// before the identity check, which for a Guest would cost a full setup.
#[test]
fn a_pinned_content_hash_refuses_other_bytes_unchecked() {
    let mut bytes = b"\0asm".to_vec();
    bytes.resize(1_000, 7);
    let identity = ExpectedIdentity::Runtime(neutrin0_primitives::blake3_256(&bytes));
    let requester = backend();
    start_pinned(&requester, identity, Some([3; 32]));
    let item = requester.next_program_fetch().unwrap();
    assert!(requester.absorb_fetched_fragment(&fragment(item, &bytes, bytes.len() as u64)));
    assert!(requester.program_store().read_identity(identity).is_none());
    let pinned = crate::programs::content_hash(&bytes);
    let accepted = backend();
    start_pinned(&accepted, identity, pinned);
    let item = accepted.next_program_fetch().unwrap();
    assert!(accepted.absorb_fetched_fragment(&fragment(item, &bytes, bytes.len() as u64)));
    assert_eq!(
        accepted.program_store().read_identity(identity),
        Some(bytes)
    );
}
