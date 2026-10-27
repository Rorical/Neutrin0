//! Consensus chunk guest, for complete execution and consensus validation.
//!
//! Historical sanctions and votes open authenticated history and replay state.
//! The verifier compares the committed chain binding with its own; the receipt
//! then proves the chain from the specification's start to its end boundary.

#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use neutrin0_prover_chunk::consensus::{
    ChunkReceiptStatement, ConsensusWitness, MAX_CHUNK_WITNESS_BYTES, validate_consensus,
};
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

fn main() {
    let bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    // Voters checked this bound before certifying the chunk.
    assert!(
        bytes.len() <= MAX_CHUNK_WITNESS_BYTES,
        "chunk witness exceeds the Guest input bound"
    );
    let input: ConsensusWitness = borsh::from_slice(&bytes).expect("canonical chunk witness");
    // Design 08: the chunk prover's account is committed outside the
    // consensus statement, so every prover of one certificate finalizes the
    // same chunk and proves the same History.
    let chunk_prover_address: [u8; 32] = sp1_zkvm::io::read_vec()
        .try_into()
        .expect("32-byte chunk prover address");
    let statement = validate_consensus(&input).expect("valid consensus transition");
    for block in &input.blocks {
        let public_values = borsh::to_vec(&block.statement()).expect("canonical block receipt");
        let digest: [u8; 32] = Sha256::digest(&public_values).into();
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.context.programs.execution.block, &digest);
    }
    // Fact statements answered signature checks above; authenticate each one
    // under the specification's Fact Guest in the order the host attached them.
    for fact in &input.facts {
        let public_values = borsh::to_vec(fact).expect("canonical fact statement");
        let digest: [u8; 32] = Sha256::digest(&public_values).into();
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.chain_spec.genesis_execution.fact, &digest);
    }
    // Design 08: the ratified chunk proof is verified, not trusted; its
    // public values were bound to this chain and boundary above. The first
    // chunk starts at the specification's pinned boundary, so this recursion
    // makes every receipt a proof of the whole chain from there (design 13).
    for ratified in &input.ratified {
        let public_values = borsh::to_vec(ratified).expect("canonical chunk receipt statement");
        let digest: [u8; 32] = Sha256::digest(&public_values).into();
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.chain_spec.genesis_chunk, &digest);
    }
    let output = borsh::to_vec(&ChunkReceiptStatement {
        statement,
        chunk_prover_address,
    })
    .expect("canonical chunk receipt statement");
    sp1_zkvm::io::commit_slice(&output);
}
