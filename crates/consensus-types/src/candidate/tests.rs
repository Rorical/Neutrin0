use super::*;
use crate::{AggregatedVote, FinalityVoteData, FinalityVotePhase};
use neutrin0_primitives::BitVec;

fn candidate() -> BftCandidate {
    BftCandidate {
        round: 1,
        chunk: Chunk {
            next_identity_sanctions_root: [0; 32],

            chunk_id: 0,
            start_height: 1,
            end_height: 2,
            start_state_root: [0; 32],
            end_state_root: [1; 32],
            start_block_hash: [2; 32],
            end_block_hash: [3; 32],
            block_hash_root: [4; 32],
            block_proof_root: [5; 32],
            vrf_proof_root: [6; 32],
            active_validator_set_root: [7; 32],
            next_validator_set_root: [7; 32],
            da_root: [8; 32],
        },
        justification: Some(QuorumCertificate {
            data: FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: [9; 32],
                selection: [0; 32],
                phase: FinalityVotePhase::Prevote,
            },
            aggregate: AggregatedVote {
                aggregation_bits: BitVec::from_bytes(3, alloc::vec![7]).unwrap(),
                signature: [10; 96],
            },
        }),
        selection: Some(PaymentSelection::default()),
    }
}

#[test]
fn candidate_wire_roundtrip_preserves_exact_quorum() {
    let candidate = candidate();
    assert_eq!(
        borsh::from_slice::<BftCandidate>(&borsh::to_vec(&candidate).unwrap()).unwrap(),
        candidate
    );
}

#[test]
fn oversized_bitmap_is_rejected_before_reading_its_payload() {
    let candidate = candidate();
    let mut bytes = borsh::to_vec(&candidate.chunk).unwrap();
    bytes.extend(borsh::to_vec(&candidate.round).unwrap());
    bytes.push(1);
    bytes.extend(borsh::to_vec(&candidate.justification.unwrap().data).unwrap());
    bytes.extend((MAX_CANDIDATE_SIGNERS + 1).to_le_bytes());
    bytes.extend(u32::MAX.to_le_bytes());
    let error = borsh::from_slice::<BftCandidate>(&bytes).unwrap_err();
    assert_eq!(error.kind(), borsh::io::ErrorKind::InvalidData);
}

#[test]
fn inconsistent_bitmap_length_and_padding_are_rejected() {
    let candidate = candidate();
    let mut prefix = borsh::to_vec(&candidate.chunk).unwrap();
    prefix.extend(borsh::to_vec(&candidate.round).unwrap());
    prefix.push(1);
    prefix.extend(borsh::to_vec(&candidate.justification.unwrap().data).unwrap());
    let mut wrong_length = prefix.clone();
    wrong_length.extend(1_u32.to_le_bytes());
    wrong_length.extend(2_u32.to_le_bytes());
    assert!(borsh::from_slice::<BftCandidate>(&wrong_length).is_err());
    prefix.extend(1_u32.to_le_bytes());
    prefix.extend(1_u32.to_le_bytes());
    prefix.push(255);
    assert_eq!(
        borsh::from_slice::<BftCandidate>(&prefix)
            .unwrap_err()
            .kind(),
        borsh::io::ErrorKind::InvalidData
    );
}
