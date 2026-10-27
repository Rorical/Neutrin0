use super::*;
use neutrin0_crypto::bls::{SecretKey, aggregate_public_keys, aggregate_signatures};
use neutrin0_prover_chunk::{
    bls::DirectVerifier,
    facts::{FactRecorder, FactRequest},
};

const G1_IDENTITY: BlsPublicKey = {
    let mut bytes = [0; 48];
    bytes[0] = 0xc0;
    bytes
};
const G2_IDENTITY: BlsSignature = {
    let mut bytes = [0; 96];
    bytes[0] = 0xc0;
    bytes
};
// (x, y) = (0, 2) is an on-curve order-three G1 point, outside the subgroup.
const G1_TORSION: BlsPublicKey = {
    let mut bytes = [0; 48];
    bytes[0] = 0x80;
    bytes
};

#[test]
fn native_verdicts_match_portable_domains_and_malformed_encodings() {
    assert_eq!(
        neutrin0_crypto::bls::SIG_DST,
        neutrin0_prover_chunk::bls::SIG_DST
    );
    assert_eq!(
        neutrin0_crypto::bls::POP_DST,
        neutrin0_prover_chunk::bls::POP_DST
    );
    let sk = SecretKey::key_gen(&[17; 32], &[]).unwrap();
    let key = sk.public_key().to_bytes();
    let signature = sk.sign(b"vote").to_bytes();
    let pop = sk.prove_possession().to_bytes();
    let mut native = NativeBlstVerifier;
    let mut portable = DirectVerifier::default();
    assert!(native.verify(&key, b"vote", &signature));
    assert!(native.pop(&key, &pop));
    assert!(!native.verify(&key, b"wrong", &signature));
    assert!(!native.pop(&key, &signature));
    assert!(!native.verify(&G1_TORSION, b"vote", &signature));
    let mut noncanonical_key = key;
    noncanonical_key[0] &= 0x7f;
    let mut noncanonical_signature = signature;
    noncanonical_signature[0] &= 0x7f;
    for key in [
        key,
        G1_IDENTITY,
        G1_TORSION,
        [0; 48],
        [0xff; 48],
        noncanonical_key,
    ] {
        for signature in [
            signature,
            pop,
            G2_IDENTITY,
            [0; 96],
            [0xff; 96],
            noncanonical_signature,
        ] {
            assert_eq!(
                native.verify(&key, b"vote", &signature),
                portable.verify(&key, b"vote", &signature)
            );
            assert_eq!(
                native.verify(&key, b"other", &signature),
                portable.verify(&key, b"other", &signature)
            );
            assert_eq!(native.pop(&key, &signature), portable.pop(&key, &signature));
        }
    }
}

#[test]
fn native_aggregate_and_recorded_negative_verdicts_match_portable() {
    let a = SecretKey::key_gen(&[18; 32], &[]).unwrap();
    let b = SecretKey::key_gen(&[19; 32], &[]).unwrap();
    let keys = [a.public_key().to_bytes(), b.public_key().to_bytes()];
    let signatures = [a.sign(b"vote"), b.sign(b"vote")];
    let aggregate = aggregate_signatures(&[&signatures[0], &signatures[1]])
        .unwrap()
        .to_bytes();
    let mut native = NativeBlstVerifier;
    let mut portable = DirectVerifier::default();
    assert!(native.aggregate(&keys, b"vote", &aggregate));
    assert!(!native.aggregate(&keys, b"wrong", &aggregate));
    for selected in [keys.as_slice(), &keys[..1], &[], &[G1_IDENTITY], &[[0; 48]]] {
        for signature in [aggregate, G2_IDENTITY, [0; 96], [0xff; 96]] {
            assert_eq!(
                native.aggregate(selected, b"vote", &signature),
                portable.aggregate(selected, b"vote", &signature)
            );
        }
    }
    // A checked aggregate key is also a valid single signer input.
    let combined = aggregate_public_keys(&[&a.public_key(), &b.public_key()])
        .unwrap()
        .to_bytes();
    assert_eq!(
        native.verify(&combined, b"vote", &aggregate),
        portable.verify(&combined, b"vote", &aggregate)
    );
    let request = FactRequest::Signature {
        key: keys[0],
        message: b"wrong".to_vec(),
        signature: signatures[0].to_bytes(),
        possession: false,
    };
    let mut recorder = FactRecorder::with_verifier(std::collections::BTreeMap::default(), native);
    assert!(!recorder.check(request.clone()));
    assert_eq!(recorder.finish().unwrap(), vec![(request, false)]);
}

#[test]
fn native_aggregate_rejects_cancelling_public_keys() {
    let mut one = [0; 32];
    one[31] = 1;
    let a = SecretKey::from_bytes(&one).unwrap();
    let negative_one =
        hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")
            .unwrap()
            .try_into()
            .unwrap();
    let b = SecretKey::from_bytes(&negative_one).unwrap();
    let keys = [a.public_key().to_bytes(), b.public_key().to_bytes()];
    let signature = a.sign(b"vote").to_bytes();
    assert!(!NativeBlstVerifier.aggregate(&keys, b"vote", &signature));
    assert!(!DirectVerifier::default().aggregate(&keys, b"vote", &signature));
}
