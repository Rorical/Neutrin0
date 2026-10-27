use super::{proposer_lease, select_receipt};
use crate::store::StoredReceipt;
use neutrin0_consensus_types::{BlockProof, BlockProofPublicInputs, Header};
use neutrin0_primitives::{Hash, ZERO_HASH};

const PROPOSER: Hash = [0x11; 32];
const EXCLUSIVE: u64 = 32;

fn header(slot: u64) -> Header {
    Header {
        height: 1,
        slot,
        parent_hash: ZERO_HASH,
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: ZERO_HASH,
        transactions_root: ZERO_HASH,
        votes_root: ZERO_HASH,
        da_root: ZERO_HASH,
        runtime_extra: ZERO_HASH,
        inputs_root: [0; 32],
        receipts_root: ZERO_HASH,
        gas_used: 0,
        gas_limit: 1,
        timestamp: 0,
        signature: [0; 96],
    }
}

fn receipt(prover_address: Hash, key: u8, first_verified_slot: u64) -> StoredReceipt {
    StoredReceipt {
        proof: BlockProof {
            height: 1,
            block_hash: ZERO_HASH,
            public_inputs: BlockProofPublicInputs {
                context: Box::default(),
                chain_id: 1,
                height: 1,
                parent_block_hash: ZERO_HASH,
                block_hash: ZERO_HASH,
                state_root_before: ZERO_HASH,
                state_root_after: ZERO_HASH,
                transactions_root: ZERO_HASH,
                receipt_root: ZERO_HASH,
                da_root: ZERO_HASH,
                vm_code_hash: ZERO_HASH,
                block_program: [0; 8],
                gas_used: 0,
                gas_limit: 1,
                proposer_address: PROPOSER,
                runtime_extra: ZERO_HASH,
                inputs_root: [0; 32],
            },
            prover_address,
            statement_key: [key; 32],
            proof_bytes: vec![key],
        },
        first_verified_slot,
    }
}

#[test]
fn proposers_receipt_wins_regardless_of_key_or_window() {
    let header = header(10);
    let held = [receipt([0x22; 32], 1, 10), receipt(PROPOSER, 9, 11)];
    let inside = select_receipt(&header, &held, 11, EXCLUSIVE, None).unwrap();
    assert_eq!(inside.proof.statement_key, [9; 32]);
    let after = select_receipt(
        &header,
        &held,
        10 + EXCLUSIVE + 5,
        EXCLUSIVE,
        Some([0x22; 32]),
    )
    .unwrap();
    assert_eq!(after.proof.statement_key, [9; 32]);
}

#[test]
fn third_party_receipts_wait_for_the_exclusive_window() {
    let header = header(10);
    let held = [receipt([0x22; 32], 1, 10)];
    assert!(select_receipt(&header, &held, 10 + EXCLUSIVE - 1, EXCLUSIVE, None).is_none());
    let selected = select_receipt(&header, &held, 10 + EXCLUSIVE, EXCLUSIVE, None).unwrap();
    assert_eq!(selected.proof.statement_key, [1; 32]);
}

#[test]
fn after_the_window_the_leader_prefers_its_own_receipt_then_the_earliest() {
    let header = header(10);
    let held = [
        receipt([0x22; 32], 5, 10),
        receipt([0x33; 32], 2, 12),
        receipt([0x44; 32], 7, 9),
    ];
    let own = select_receipt(&header, &held, 10 + EXCLUSIVE, EXCLUSIVE, Some([0x33; 32])).unwrap();
    assert_eq!(own.proof.statement_key, [2; 32]);
    let earliest = select_receipt(&header, &held, 10 + EXCLUSIVE, EXCLUSIVE, None).unwrap();
    assert_eq!(earliest.proof.statement_key, [7; 32]);
    assert!(select_receipt(&header, &[], 10 + EXCLUSIVE, EXCLUSIVE, None).is_none());
}

#[test]
fn a_proposer_receipt_arriving_after_a_rescue_loses_its_priority() {
    let header = header(10);
    let lease = proposer_lease(EXCLUSIVE);
    // Inside the lease the proposer's receipt wins over an earlier one.
    let early = [
        receipt([0x22; 32], 1, 10),
        receipt(PROPOSER, 9, 10 + lease - 1),
    ];
    let chosen = select_receipt(&header, &early, 10 + EXCLUSIVE, EXCLUSIVE, None).unwrap();
    assert_eq!(chosen.proof.statement_key, [9; 32]);
    // After the lease, a receipt someone else proved first keeps the block.
    let rescued = [
        receipt([0x22; 32], 1, 10 + lease + 4),
        receipt(PROPOSER, 9, 10 + lease + 6),
    ];
    let chosen = select_receipt(&header, &rescued, 10 + EXCLUSIVE, EXCLUSIVE, None).unwrap();
    assert_eq!(chosen.proof.statement_key, [1; 32]);
    // A late proposer receipt that still arrived first keeps priority.
    let slow = [
        receipt(PROPOSER, 9, 10 + lease + 2),
        receipt([0x22; 32], 1, 10 + lease + 4),
    ];
    let chosen = select_receipt(&header, &slow, 10 + EXCLUSIVE, EXCLUSIVE, None).unwrap();
    assert_eq!(chosen.proof.statement_key, [9; 32]);
}
