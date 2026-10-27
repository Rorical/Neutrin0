use super::*;
use crate::bft::ReceiptChoice;
use crate::{AggregatedVote, FinalityVoteData, FinalityVotePhase};
use alloc::vec;
use neutrin0_primitives::BitVec;

const fn ratification(chunk_id: u64) -> ChunkRatification {
    ChunkRatification {
        chunk_id,
        prover_address: [chunk_id as u8; 32],
        finality_cert_hash: [0xdd; 32],
        statement_key: [0xee; 32],
    }
}

const fn validator(byte: u8, effective_stake: u128) -> Validator {
    Validator {
        pubkey: [byte; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([byte; 20]),
        effective_stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

const fn chunk(start_height: u64, end_height: u64) -> Chunk {
    Chunk {
        chunk_id: 3,
        start_height,
        end_height,
        start_state_root: [0; 32],
        end_state_root: [0; 32],
        start_block_hash: [0; 32],
        end_block_hash: [0; 32],
        block_hash_root: [0; 32],
        block_proof_root: [0; 32],
        vrf_proof_root: [0; 32],
        active_validator_set_root: [0; 32],
        next_validator_set_root: [0; 32],
        next_identity_sanctions_root: [0; 32],
        da_root: [0; 32],
    }
}

fn carried(chunk: &Chunk, receipts: usize) -> CarriedCertificate {
    let proposal = CompactProposal {
        round: 0,
        proposer_index: 0,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: 40,
        receipts: (0..receipts)
            .map(|index| ReceiptChoice {
                prover_address: [0x10 + index as u8; 32],
                statement_key: [index as u8; 32],
            })
            .collect(),
        ratified_chunk_proofs: vec![ratification(2)],
        signature: [0; 96],
    };
    CarriedCertificate {
        quorum: QuorumCertificate {
            data: FinalityVoteData {
                chunk_id: chunk.chunk_id,
                round: 0,
                chunk_hash: chunk.hash(),
                selection: proposal.selection(),
                phase: FinalityVotePhase::Precommit,
            },
            aggregate: AggregatedVote {
                aggregation_bits: BitVec::from_bytes(3, vec![0b001]).unwrap(),
                signature: [0; 96],
            },
        },
        proposal,
    }
}

#[test]
fn a_certificate_ratifies_exactly_the_previous_chunk() {
    assert!(ratifies_previous(&[], None));
    assert!(ratifies_previous(&[ratification(6)], Some(6)));
    // The first chunk ratifies nothing; every later one ratifies its
    // predecessor, never an empty list, an older chunk, its own chunk or a
    // second entry.
    assert!(!ratifies_previous(&[ratification(0)], None));
    assert!(!ratifies_previous(&[], Some(6)));
    assert!(!ratifies_previous(&[ratification(5)], Some(6)));
    assert!(!ratifies_previous(&[ratification(7)], Some(6)));
    assert!(!ratifies_previous(
        &[ratification(6), ratification(6)],
        Some(6)
    ));
}

#[test]
fn report_follows_the_signed_selection_and_the_whole_committee() {
    let mut validators = [validator(1, 5), validator(2, 7), validator(3, 11)];
    validators[1].effective_stake = 0;
    let chunk = chunk(8, 10);
    // The carried quorum holds one signer; the report pays the whole
    // unslashed committee by weight, whichever subset a carrier attaches.
    let report = ProvingReport::from_certificate(&chunk, &validators, &carried(&chunk, 3)).unwrap();
    assert_eq!(report.chunk_id, 3);
    assert_eq!(
        report.entries,
        vec![
            ProvingEntry {
                height: 8,
                prover: [0x10; 32]
            },
            ProvingEntry {
                height: 9,
                prover: [0x11; 32]
            },
            ProvingEntry {
                height: 10,
                prover: [0x12; 32]
            },
        ]
    );
    assert_eq!(
        report.committee,
        vec![
            (neutrin0_primitives::runtime_account([1; 20]), 5),
            (neutrin0_primitives::runtime_account([3; 20]), 11)
        ]
    );
    assert_eq!(report.chunk_provers, vec![(2, [2; 32])]);
    assert_ne!(report.commitment(), NO_PROVING);

    // A selection the quorum did not sign, a quorum over another chunk or
    // a receipt list that does not cover the range derives nothing.
    let mut unsigned = carried(&chunk, 3);
    unsigned.proposal.receipts[0].prover_address = [0x99; 32];
    assert_eq!(
        ProvingReport::from_certificate(&chunk, &validators, &unsigned),
        None
    );
    let mut foreign = carried(&chunk, 3);
    foreign.quorum.data.chunk_hash[0] ^= 1;
    assert_eq!(
        ProvingReport::from_certificate(&chunk, &validators, &foreign),
        None
    );
    for receipts in [2, 4] {
        assert_eq!(
            ProvingReport::from_certificate(&chunk, &validators, &carried(&chunk, receipts)),
            None
        );
    }
}
