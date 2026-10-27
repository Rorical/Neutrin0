use super::*;
use neutrin0_crypto::sha256;

fn dummy_proof(byte: u8) -> BlsSignature {
    [byte; 96]
}

#[test]
fn fold_seed_is_deterministic() {
    let prev = [0x11; 32];
    let proofs = [dummy_proof(0xAA), dummy_proof(0xBB)];
    let a = fold_seed(&prev, &proofs);
    let b = fold_seed(&prev, &proofs);
    assert_eq!(a, b);
}

#[test]
fn fold_seed_with_no_proofs_equals_sha256_of_prev_seed() {
    let prev = [0x33; 32];
    let folded = fold_seed(&prev, &[]);
    assert_eq!(folded, sha256(&prev));
}

#[test]
fn fold_seed_order_matters() {
    let prev = [0x77; 32];
    let a = fold_seed(&prev, &[dummy_proof(0x01), dummy_proof(0x02)]);
    let b = fold_seed(&prev, &[dummy_proof(0x02), dummy_proof(0x01)]);
    assert_ne!(a, b);
}

#[test]
fn fold_seed_changes_with_one_bit_flip_in_prev() {
    let mut prev = [0x55; 32];
    let proofs = [dummy_proof(0xCC)];
    let a = fold_seed(&prev, &proofs);
    prev[0] ^= 0x01;
    let b = fold_seed(&prev, &proofs);
    assert_ne!(a, b);
}

#[test]
fn fold_seed_changes_with_one_bit_flip_in_a_proof() {
    let prev = [0x99; 32];
    let mut proofs = [dummy_proof(0x00), dummy_proof(0x00)];
    let a = fold_seed(&prev, &proofs);
    proofs[1][95] ^= 0x80;
    let b = fold_seed(&prev, &proofs);
    assert_ne!(a, b);
}

#[test]
fn fold_seed_matches_explicit_concatenated_sha256() {
    let prev = [0x11; 32];
    let proofs = [dummy_proof(0xAA), dummy_proof(0xBB)];
    let folded = fold_seed(&prev, &proofs);

    let mut concatenated = alloc::vec::Vec::with_capacity(32 + 96 * 2);
    concatenated.extend_from_slice(&prev);
    for p in &proofs {
        concatenated.extend_from_slice(p);
    }
    assert_eq!(folded, sha256(&concatenated));
}
