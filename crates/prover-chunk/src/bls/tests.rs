use super::*;
use neutrin0_crypto::bls::{SecretKey, aggregate_signatures};

#[test]
fn agrees_with_host_signatures_and_domains() {
    let key = SecretKey::key_gen(&[7; 32], &[]).unwrap();
    let pk = key.public_key().to_bytes();
    let sig = key.sign(b"chunk").to_bytes();
    assert!(verify(&pk, b"chunk", &sig));
    assert!(!verify(&pk, b"other", &sig));
    assert!(verify_pop(&pk, &key.prove_possession().to_bytes()));
    assert!(!verify(&pk, &pk, &key.prove_possession().to_bytes()));
    assert!(!verify_pop(&pk, &key.sign(&pk).to_bytes()));
    let registration = key.prove_registration(&[7; 32]).to_bytes();
    assert!(verify_registration_pop(&pk, &[7; 32], &registration));
    assert!(!verify_registration_pop(&pk, &[8; 32], &registration));
    assert!(!verify_registration_pop(
        &pk,
        &[7; 32],
        &key.prove_possession().to_bytes()
    ));
}

#[test]
fn agrees_with_host_aggregates_and_rejects_wrong_membership() {
    let first = SecretKey::key_gen(&[1; 32], &[]).unwrap();
    let second = SecretKey::key_gen(&[2; 32], &[]).unwrap();
    let keys = [
        first.public_key().to_bytes(),
        second.public_key().to_bytes(),
    ];
    let a = first.sign(b"vote");
    let b = second.sign(b"vote");
    let aggregate = aggregate_signatures(&[&a, &b]).unwrap().to_bytes();
    assert!(fast_aggregate_verify(&keys, b"vote", &aggregate));
    assert!(!fast_aggregate_verify(&keys[..1], b"vote", &aggregate));
    assert!(!fast_aggregate_verify(&[], b"vote", &aggregate));
    assert!(!fast_aggregate_verify(&keys, b"other", &aggregate));
}

#[test]
fn rejects_identity_and_invalid_encodings() {
    let pk = G1Affine::identity().to_compressed();
    let sig = G2Affine::identity().to_compressed();
    assert!(!verify(&pk, b"", &sig));
    assert!(!verify(&[0; 48], b"", &[0; 96]));
    assert!(!fast_aggregate_verify(&[pk], b"", &sig));
}
