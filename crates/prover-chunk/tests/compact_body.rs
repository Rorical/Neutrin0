//! Adversarial binding tests for omission of ordinary transactions from chunks.
pub mod support;

use neutrin0_consensus_types::Body;
use neutrin0_prover_chunk::{body::ConsensusBody, consensus::body_da_root};
use neutrin0_runtime_abi::RuntimeTransaction;
use neutrin0_runtime_core::execution::transaction_commitments;

fn ordinary(nonce: u64) -> RuntimeTransaction {
    support::transfer(nonce)
}

fn body(transactions: &[RuntimeTransaction]) -> Body {
    Body {
        transactions: transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    }
}

#[test]
fn compact_witness_size_is_independent_of_ordinary_transaction_count() {
    let mut sizes = Vec::new();
    for count in [0, 1, 128, 1024] {
        let (witness, _, _) = support::fixture_with_transactions(
            [1; 8],
            [4; 32],
            (0..count).map(ordinary).collect(),
            30_000_000,
        );
        neutrin0_prover_chunk::consensus::validate_consensus(&witness).unwrap();
        sizes.push(borsh::to_vec(&witness).unwrap().len());
    }
    assert!(sizes.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn omitted_transactions_remain_bound_by_block_count_and_da_root() {
    let (fixture, _, _) = support::fixture([1; 8], [4; 32]);
    let txs = vec![ordinary(0), ordinary(1)];
    let full = body(&txs);
    let compact = ConsensusBody::from_body(&full).unwrap();
    let (root, summary) = transaction_commitments(&txs);
    let mut header = fixture.blocks[0].header.clone();
    header.transactions_root = root;
    header.da_root = body_da_root(&full);
    compact.validate(&header, &summary).unwrap();
    let mut wrong_count = summary;
    wrong_count.transaction_count ^= 1;
    assert!(compact.validate(&header, &wrong_count).is_err());
    header.transactions_root[0] ^= 1;
    assert!(compact.validate(&header, &summary).is_err());
}

#[test]
fn compact_body_accepts_other_runtimes_without_decoding_user_payloads() {
    let tx = neutrin0_runtime_abi::RuntimeTransaction::User(b"foreign-runtime-call".to_vec());
    let body = neutrin0_consensus_types::Body {
        transactions: vec![borsh::to_vec(&tx).unwrap()],
        ..Default::default()
    };
    assert!(neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).is_ok());
    let mut malformed = body;
    malformed.transactions[0].push(0); // a common envelope must still be exact
    assert!(neutrin0_prover_chunk::body::ConsensusBody::from_body(&malformed).is_err());
}
