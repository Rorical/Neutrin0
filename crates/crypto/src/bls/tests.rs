use super::*;
use getrandom::SysRng;
use rand_core::UnwrapErr;

fn gen_sk() -> SecretKey {
    SecretKey::generate(&mut UnwrapErr(SysRng))
}

#[test]
fn keygen_sign_verify_roundtrips() {
    let sk = gen_sk();
    let pk = sk.public_key();
    let msg = b"hello, neutrin0";
    let sig = sk.sign(msg);
    pk.verify(msg, &sig).expect("verify");
}

#[test]
fn signing_is_deterministic() {
    // BLS signatures are unique: same (sk, msg) → same sig. This is the
    // property that makes BLS-VRF work.
    let sk = gen_sk();
    let s1 = sk.sign(b"abc");
    let s2 = sk.sign(b"abc");
    assert_eq!(s1.to_bytes(), s2.to_bytes());
}

#[test]
fn verify_fails_on_tampered_message() {
    let sk = gen_sk();
    let pk = sk.public_key();
    let sig = sk.sign(b"original");
    assert_eq!(pk.verify(b"tampered", &sig), Err(CryptoError::Verification));
}

#[test]
fn verify_fails_on_wrong_pubkey() {
    let sk1 = gen_sk();
    let sk2 = gen_sk();
    let msg = b"msg";
    let sig = sk1.sign(msg);
    assert_eq!(
        sk2.public_key().verify(msg, &sig),
        Err(CryptoError::Verification)
    );
}

#[test]
fn proof_of_possession_roundtrips() {
    let sk = gen_sk();
    let pk = sk.public_key();
    let pop = sk.prove_possession();
    pk.verify_pop(&pop).expect("verify_pop");
}

#[test]
fn registration_proof_binds_the_registering_address() {
    let sk = gen_sk();
    let pk = sk.public_key();
    let proof = sk.prove_registration(&[1; 32]);
    pk.verify_registration(&[1; 32], &proof)
        .expect("verify_registration");
    assert!(pk.verify_registration(&[2; 32], &proof).is_err());
    assert!(pk.verify_pop(&proof).is_err());
    assert!(
        pk.verify_registration(&[1; 32], &sk.prove_possession())
            .is_err()
    );
}

#[test]
fn pop_under_different_dst_does_not_verify_as_sig() {
    // A PoP must not be accepted as a regular signature over the same
    // message bytes, because the DST is different. This guards against
    // a cross-protocol replay where an adversary tries to use a
    // registration PoP as a normal signature.
    let sk = gen_sk();
    let pk = sk.public_key();
    let pop = sk.prove_possession();
    // PoP's signed bytes are exactly the 48-byte pubkey; treat those
    // bytes as a "message" and confirm verify rejects.
    let pk_bytes = pk.to_bytes();
    assert_eq!(pk.verify(&pk_bytes, &pop), Err(CryptoError::Verification));
}

#[test]
fn pop_cross_verify_fails_with_wrong_pubkey() {
    let sk1 = gen_sk();
    let sk2 = gen_sk();
    let pop = sk1.prove_possession();
    assert_eq!(
        sk2.public_key().verify_pop(&pop),
        Err(CryptoError::Verification)
    );
}

#[test]
fn keygen_rejects_short_ikm() {
    let short = [7_u8; 16];
    match SecretKey::key_gen(&short, &[]) {
        Err(CryptoError::UnexpectedLength {
            actual: 16,
            expected: 32,
        }) => {}
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn keygen_is_deterministic_and_binds_key_info() {
    let ikm = [9_u8; 32];
    let sk1 = SecretKey::key_gen(&ikm, b"validator").expect("valid");
    let sk2 = SecretKey::key_gen(&ikm, b"validator").expect("valid");
    let sk3 = SecretKey::key_gen(&ikm, b"node").expect("valid");
    assert_eq!(sk1.to_bytes(), sk2.to_bytes());
    assert_ne!(sk1.to_bytes(), sk3.to_bytes());
}

#[test]
fn secret_key_from_bytes_rejects_zero_scalar() {
    let zero = [0_u8; 32];
    assert!(matches!(
        SecretKey::from_bytes(&zero),
        Err(CryptoError::InvalidSecretKey)
    ));
}

#[test]
fn secret_key_roundtrips_bytes() {
    let sk1 = gen_sk();
    let sk2 = SecretKey::from_bytes(&sk1.to_bytes()).expect("valid");
    assert_eq!(sk1.public_key().to_bytes(), sk2.public_key().to_bytes());
}

#[test]
fn public_key_roundtrips_bytes() {
    let sk = gen_sk();
    let pk1 = sk.public_key();
    let pk2 = PublicKey::from_bytes(&pk1.to_bytes()).expect("valid");
    assert_eq!(pk1.to_bytes(), pk2.to_bytes());
}

#[test]
fn signature_roundtrips_bytes() {
    let sk = gen_sk();
    let sig1 = sk.sign(b"msg");
    let sig2 = Signature::from_bytes(&sig1.to_bytes()).expect("valid");
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn public_key_from_bytes_rejects_identity() {
    let identity = [0_u8; 48];
    assert_eq!(
        PublicKey::from_bytes(&identity),
        Err(CryptoError::InvalidPublicKey)
    );
}

#[test]
fn signature_from_bytes_rejects_bit_flipped_encoding() {
    let sk = gen_sk();
    let mut bytes = sk.sign(b"msg").to_bytes();
    bytes[0] ^= 0x80;
    assert_eq!(
        Signature::from_bytes(&bytes),
        Err(CryptoError::InvalidSignature)
    );
}

#[test]
fn signature_from_bytes_rejects_identity() {
    let identity = [0_u8; 96];
    // The all-zero encoding decodes to an infinity-flagged garbage; blst's
    // from_bytes path rejects it. `validate(true)` would also reject the
    // identity point. Either path returns InvalidSignature.
    let bytes: BlsSignature = identity;
    assert_eq!(
        Signature::from_bytes(&bytes),
        Err(CryptoError::InvalidSignature)
    );
}

#[test]
fn fast_aggregate_verify_succeeds_for_shared_message() {
    let sks: Vec<SecretKey> = (0..16).map(|_| gen_sk()).collect();
    let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let msg = b"shared finality vote payload";
    let sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(msg)).collect();
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = aggregate_signatures(&sig_refs).expect("aggregate");
    fast_aggregate_verify(&pk_refs, msg, &agg).expect("verify aggregate");
}

#[test]
fn aggregate_public_key_verifies_shared_message_signature() {
    let sks: Vec<SecretKey> = (0..4).map(|_| gen_sk()).collect();
    let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let msg = b"shared aggregate pubkey path";
    let sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(msg)).collect();
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg_sig = aggregate_signatures(&sig_refs).expect("aggregate sig");
    let agg_pk = aggregate_public_keys(&pk_refs).expect("aggregate pk");
    agg_pk
        .verify(msg, &agg_sig)
        .expect("verify via aggregate pk");
}

#[test]
fn fast_aggregate_verify_fails_when_one_signer_signed_wrong_message() {
    let sks: Vec<SecretKey> = (0..4).map(|_| gen_sk()).collect();
    let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let msg = b"vote-A";
    let mut sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(msg)).collect();
    // Replace last signer's signature with one over a different message.
    sigs[3] = sks[3].sign(b"vote-B");
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = aggregate_signatures(&sig_refs).expect("aggregate");
    assert_eq!(
        fast_aggregate_verify(&pk_refs, msg, &agg),
        Err(CryptoError::Verification)
    );
}

#[test]
fn aggregate_verify_succeeds_for_distinct_messages() {
    let sks: Vec<SecretKey> = (0..8).map(|_| gen_sk()).collect();
    let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let messages: Vec<Vec<u8>> = (0..8).map(|i| format!("msg-{i}").into_bytes()).collect();
    let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let sigs: Vec<Signature> = sks
        .iter()
        .zip(messages.iter())
        .map(|(sk, m)| sk.sign(m))
        .collect();
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = aggregate_signatures(&sig_refs).expect("aggregate");
    aggregate_verify(&pk_refs, &msg_refs, &agg).expect("verify");
}

#[test]
fn aggregate_verify_fails_when_public_key_set_does_not_match_signers() {
    let sks: Vec<SecretKey> = (0..4).map(|_| gen_sk()).collect();
    let mut pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
    pks[3] = gen_sk().public_key();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let messages: Vec<Vec<u8>> = (0..4).map(|i| format!("msg-{i}").into_bytes()).collect();
    let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let sigs: Vec<Signature> = sks
        .iter()
        .zip(messages.iter())
        .map(|(sk, m)| sk.sign(m))
        .collect();
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = aggregate_signatures(&sig_refs).expect("aggregate");
    assert_eq!(
        aggregate_verify(&pk_refs, &msg_refs, &agg),
        Err(CryptoError::Verification)
    );
}

#[test]
fn secret_key_debug_does_not_leak_scalar() {
    let ikm = [0x55_u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).expect("valid");
    let debug = format!("{sk:?}");
    assert!(!debug.contains(&hex::encode(sk.to_bytes())));
    assert!(debug.contains("pubkey"));
}

#[test]
fn aggregate_verify_fails_on_length_mismatch() {
    let sks: Vec<SecretKey> = (0..3).map(|_| gen_sk()).collect();
    let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let msgs: Vec<&[u8]> = vec![b"a", b"b"];
    let sig = sks[0].sign(b"a");
    assert_eq!(
        aggregate_verify(&pk_refs, &msgs, &sig),
        Err(CryptoError::UnexpectedLength {
            actual: 2,
            expected: 3
        })
    );
}

#[test]
fn aggregate_signatures_rejects_empty() {
    let empty: Vec<&Signature> = Vec::new();
    assert_eq!(aggregate_signatures(&empty), Err(CryptoError::EmptyInput));
}

#[test]
fn aggregate_public_keys_rejects_empty() {
    let empty: Vec<&PublicKey> = Vec::new();
    assert_eq!(aggregate_public_keys(&empty), Err(CryptoError::EmptyInput));
}
