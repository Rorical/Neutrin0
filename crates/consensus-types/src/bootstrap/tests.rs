use super::*;

#[test]
fn guest_fragment_identity_preserves_little_endian_words_and_namespace() {
    let digest = [0x0102_0304, 2, 3, 4, 5, 6, 7, u32::MAX];
    let guest = StateItem::guest(digest);
    assert_eq!(guest.hash[..4], [4, 3, 2, 1]);
    assert_eq!(guest.guest_digest(), Some(digest));
    assert_eq!(StateItem::runtime(guest.hash).guest_digest(), None);
    assert_eq!(
        borsh::from_slice::<StateItem>(&borsh::to_vec(&guest).unwrap()).unwrap(),
        guest
    );
    let fragment = StateEntry {
        item: guest,
        total_len: 4,
        bytes: BoundedBytes::new(alloc::vec![0x7f, b'E', b'L', b'F']).unwrap(),
    };
    assert!(fragment.validate_for(&guest));
    assert!(fragment.is_complete());
    assert!(!fragment.validate_for(&StateItem::runtime(guest.hash)));
}
use crate::history_proof::{
    ChainBinding, ChunkReceiptStatement, ConsensusBoundary, ConsensusStatement, ExecutionPrograms,
    ProgramSet,
};

fn data() -> BootstrapData {
    let boundary = ConsensusBoundary {
        identity_sanctions_root: [0; 32],

        next_chunk_id: 0,
        height: 0,
        block_hash: [1; 32],
        state_root: [2; 32],
        slot: 0,
        validators_root: [3; 32],
        seed: [4; 32],
        history_root: crate::history::empty_history_root(),
        programs: ProgramSet {
            runtime_code_hash: [6; 32],
            execution: ExecutionPrograms {
                fact: [7; 8],
                evidence: [8; 8],
                block: [9; 8],
            },
        },
        participation: crate::participation::NO_PARTICIPATION,
        proving: crate::proving::NO_PROVING,
        fork: None,
    };
    let chain = ChainBinding {
        chain_spec_hash: [5; 32],
    };
    BootstrapData::new(
        HistoryProof {
            statement: ChunkReceiptStatement {
                statement: ConsensusStatement {
                    chain,
                    start: boundary,
                    end: ConsensusBoundary {
                        next_chunk_id: 1,
                        height: 1,
                        ..boundary
                    },
                    chunk: crate::ChunkProofPublicInputs {
                        chunk_id: 0,
                        start_height: 1,
                        end_height: 1,
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
                    },
                    finality_cert_hash: [11; 32],
                },
                chunk_prover_address: [12; 32],
            },
            receipt: BoundedBytes::new(alloc::vec![1]).unwrap(),
        },
        Header {
            height: 1,
            slot: 1,
            parent_hash: [1; 32],
            proposer_index: 0,
            vrf_proof: [2; 96],
            state_root: [3; 32],
            transactions_root: [4; 32],
            votes_root: [5; 32],
            da_root: [6; 32],
            runtime_extra: [7; 32],
            inputs_root: [0; 32],
            receipts_root: [8; 32],
            gas_used: 0,
            gas_limit: 1,
            timestamp: 1,
            signature: [9; 96],
        },
        Vec::new(),
        HistoryFrontier::empty(),
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn decoding_rejects_declared_bootstrap_budgets_before_reading_payloads() {
    let base = data();
    let mut prefix = borsh::to_vec(&base).unwrap();
    // Replace the trailing empty recent-vector length.
    prefix.truncate(prefix.len() - 4);

    let mut oversized_count = prefix.clone();
    oversized_count.extend_from_slice(&9_u32.to_le_bytes());
    let error = borsh::from_slice::<BootstrapData>(&oversized_count).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let mut cumulative_overflow = prefix.clone();
    cumulative_overflow.extend_from_slice(&2_u32.to_le_bytes());
    cumulative_overflow.extend_from_slice(&1_u32.to_le_bytes());
    cumulative_overflow.push(0);
    cumulative_overflow.extend_from_slice(
        &u32::try_from(MAX_BOOTSTRAP_HISTORY_BYTES)
            .unwrap()
            .to_le_bytes(),
    );
    let error = borsh::from_slice::<BootstrapData>(&cumulative_overflow).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let mut oversized_item = prefix;
    oversized_item.extend_from_slice(&1_u32.to_le_bytes());
    oversized_item.extend_from_slice(
        &u32::try_from(MAX_BOOTSTRAP_HISTORY_BYTES + 1)
            .unwrap()
            .to_le_bytes(),
    );
    let error = borsh::from_slice::<BootstrapData>(&oversized_item).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn serialization_rejects_individually_bounded_but_oversized_history() {
    let mut base = data();
    base.recent = BootstrapHistory::new(alloc::vec![
        BoundedBytes::new(alloc::vec![0; MAX_BOOTSTRAP_HISTORY_BYTES]).unwrap(),
        BoundedBytes::new(alloc::vec![1]).unwrap(),
    ])
    .unwrap();
    assert_eq!(
        base.validate_limits(),
        Err(BoundsError {
            actual: MAX_BOOTSTRAP_HISTORY_BYTES + 1,
            max: MAX_BOOTSTRAP_HISTORY_BYTES,
        })
    );
    assert!(borsh::to_vec(&base).is_err());
}

#[test]
fn validator_length_is_bounded_before_decoding_any_validator() {
    let base = data();
    let mut encoded = borsh::to_vec(&base.history).unwrap();
    encoded.extend(borsh::to_vec(&base.anchor_header).unwrap());
    encoded.extend_from_slice(
        &u32::try_from(MAX_BOOTSTRAP_VALIDATORS + 1)
            .unwrap()
            .to_le_bytes(),
    );
    let error = borsh::from_slice::<BootstrapData>(&encoded).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn bootstrap_framing_does_not_claim_cryptographic_authentication() {
    let mut base = data();
    base.recent = BootstrapHistory::new(alloc::vec![
        BoundedBytes::new(alloc::vec![1, 2, 3,]).unwrap()
    ])
    .unwrap();
    // Transport accepts bounded opaque bytes; the installation layer must decode
    // and authenticate the actual historical opening, receipt and endpoint.
    assert_eq!(
        borsh::from_slice::<BootstrapData>(&borsh::to_vec(&base).unwrap()).unwrap(),
        base
    );
    let mut trailing = borsh::to_vec(&base).unwrap();
    trailing.push(0);
    assert!(borsh::from_slice::<BootstrapData>(&trailing).is_err());
}

fn entry(offset: u64, total_len: u64, bytes: Vec<u8>) -> StateEntry {
    StateEntry {
        item: StateItem {
            kind: StateItemKind::Value,
            hash: [1; 32],
            offset,
        },
        total_len,
        bytes: BoundedBytes::new(bytes).unwrap(),
    }
}

#[test]
fn state_fragments_bind_exact_request_and_allow_large_values() {
    let first = entry(
        0,
        2 * u64::try_from(MAX_STATE_FRAGMENT_BYTES).unwrap(),
        alloc::vec![1; MAX_STATE_FRAGMENT_BYTES],
    );
    assert!(first.validate_for(&first.item));
    assert!(!first.is_complete());
    let second = entry(
        first.end_offset().unwrap(),
        first.total_len,
        alloc::vec![2; MAX_STATE_FRAGMENT_BYTES],
    );
    assert!(second.validate_for(&second.item));
    assert!(second.is_complete());
    assert!(!second.validate_for(&first.item));
    let wrong_kind = StateItem {
        kind: StateItemKind::Node,
        ..second.item
    };
    assert!(!second.validate_for(&wrong_kind));
    let wrong_hash = StateItem {
        hash: [2; 32],
        ..second.item
    };
    assert!(!second.validate_for(&wrong_hash));
}

#[test]
fn state_fragments_reject_nonprogress_overshoot_and_offset_overflow() {
    for malformed in [
        entry(0, 1, Vec::new()),
        entry(2, 1, Vec::new()),
        entry(0, 1, alloc::vec![1, 2]),
        entry(u64::MAX, u64::MAX, alloc::vec![1]),
        // A short nonfinal fragment would let a provider split an object
        // into arbitrarily many pieces.
        entry(0, 3, alloc::vec![1, 2]),
    ] {
        assert!(!malformed.validate_for(&malformed.item));
    }
    let empty = entry(0, 0, Vec::new());
    assert!(empty.validate_for(&empty.item));
    assert!(empty.is_complete());
}

#[test]
fn state_lists_and_fragment_bytes_are_bounded_before_payload_decoding() {
    let encoded = u32::try_from(MAX_STATE_ITEMS + 1).unwrap().to_le_bytes();
    assert_eq!(
        borsh::from_slice::<StateItems>(&encoded)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        borsh::from_slice::<StateEntries>(&encoded)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let base = entry(0, u64::MAX, Vec::new());
    let mut encoded = borsh::to_vec(&base).unwrap();
    encoded.truncate(encoded.len() - 4);
    encoded.extend_from_slice(
        &u32::try_from(MAX_STATE_FRAGMENT_BYTES + 1)
            .unwrap()
            .to_le_bytes(),
    );
    assert_eq!(
        borsh::from_slice::<StateEntry>(&encoded)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}
