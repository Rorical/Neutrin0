use super::batch::{MAX_BATCH_EQUATIONS, msm_g1, msm_g2};
use super::caches::{
    CheckedSignatures, MAX_AGGREGATE_KEY_BYTES, MAX_AGGREGATE_KEYS, MAX_CHECKED_KEYS,
    MAX_CHECKED_SIGNATURES, MAX_PREPARED_MESSAGE_BYTES, MAX_PREPARED_MESSAGES, PreparedMessages,
};
use super::*;
use alloc::{rc::Rc, vec, vec::Vec};
use bls12_381::Scalar;
use neutrin0_crypto::bls::{SecretKey, aggregate_signatures};

#[test]
fn checked_point_caches_are_bounded_and_eviction_preserves_checks() {
    let mut keys = CheckedKeys::default();
    let first = G1Affine::generator().to_compressed();
    for index in 1..=MAX_CHECKED_KEYS + 1 {
        let point =
            G1Affine::from(G1Projective::generator() * Scalar::from(u64::try_from(index).unwrap()));
        assert_eq!(keys.get(&point.to_compressed()), Some(point));
    }
    assert_eq!(keys.points.len(), MAX_CHECKED_KEYS);
    assert_eq!(keys.order.len(), MAX_CHECKED_KEYS);
    assert!(!keys.points.contains_key(&first));
    assert_eq!(keys.get(&first), Some(G1Affine::generator()));
    assert!(keys.get(&G1Affine::identity().to_compressed()).is_none());
    let mut torsion = [0; 48];
    torsion[0] = 0x80; // On-curve order-three point (0, 2).
    assert!(keys.get(&torsion).is_none());

    let mut signatures = CheckedSignatures::default();
    let first = G2Affine::generator().to_compressed();
    for index in 1..=MAX_CHECKED_SIGNATURES + 1 {
        let point =
            G2Affine::from(G2Projective::generator() * Scalar::from(u64::try_from(index).unwrap()));
        assert_eq!(signatures.get(&point.to_compressed()), Some(point));
    }
    assert_eq!(signatures.points.len(), MAX_CHECKED_SIGNATURES);
    assert_eq!(signatures.order.len(), MAX_CHECKED_SIGNATURES);
    assert!(!signatures.points.contains_key(&first));
    assert_eq!(signatures.get(&first), Some(G2Affine::generator()));
    assert!(
        signatures
            .get(&G2Affine::identity().to_compressed())
            .is_none()
    );
    assert!(signatures.get(&[0xff; 96]).is_none());
}

#[test]
fn aggregate_cache_binds_exact_key_order_and_obeys_entry_and_byte_limits() {
    let mut keys = CheckedKeys::default();
    for index in 1..=MAX_AGGREGATE_KEYS + 1 {
        let point =
            G1Affine::from(G1Projective::generator() * Scalar::from(u64::try_from(index).unwrap()));
        assert_eq!(keys.aggregate(&[point.to_compressed()]), Some(point));
    }
    assert_eq!(keys.aggregates.entries.len(), MAX_AGGREGATE_KEYS);
    let point = G1Affine::generator();
    let positive = point.to_compressed();
    let negative = (-point).to_compressed();
    assert!(keys.aggregate(&[positive, negative]).is_none());
    let ordered = [positive, positive, negative];
    let reversed = [negative, positive, positive];
    assert_eq!(keys.aggregate(&ordered), Some(point));
    assert_eq!(keys.aggregate(&reversed), Some(point));
    let ordered_id = neutrin0_consensus_types::tagged_commitment(
        b"neutrin0-checked-bls-aggregate",
        ordered.as_slice(),
    );
    assert!(keys.aggregates.get(&ordered_id, &reversed).is_none());
    // Large legal inputs still compute; they are not retained if their key
    // material alone exceeds the cache's local resource budget.
    let oversized = vec![positive; MAX_AGGREGATE_KEY_BYTES / 48 + 1];
    assert!(keys.aggregate(&oversized).is_some());
    assert!(keys.aggregates.bytes <= MAX_AGGREGATE_KEY_BYTES);
    assert!(
        keys.aggregates
            .entries
            .values()
            .all(|(retained, _)| retained.len() * 48 <= MAX_AGGREGATE_KEY_BYTES)
    );
}

#[test]
fn prepared_message_cache_is_bounded_domain_separated_and_leased_locally() {
    let mut messages = PreparedMessages::default();
    let held = messages.get(b"first", SIG_DST);
    assert!(Rc::ptr_eq(&held, &messages.get(b"first", SIG_DST)));
    assert!(!Rc::ptr_eq(&held, &messages.get(b"first", POP_DST)));
    for index in 0_u64..MAX_PREPARED_MESSAGES as u64 {
        drop(messages.get(&index.to_le_bytes(), SIG_DST));
    }
    assert_eq!(messages.entries.len(), MAX_PREPARED_MESSAGES);
    let reloaded = messages.get(b"first", SIG_DST);
    assert!(!Rc::ptr_eq(&held, &reloaded));
    let expected = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        [b"first".as_slice()],
        SIG_DST,
    );
    let expected = G2Prepared::from(G2Affine::from(expected));
    assert_eq!(
        multi_miller_loop(&[(&G1Affine::generator(), held.as_ref())]).final_exponentiation(),
        multi_miller_loop(&[(&G1Affine::generator(), &expected)]).final_exponentiation()
    );
    let large = vec![7; MAX_PREPARED_MESSAGE_BYTES + 1];
    let before = messages.entries.len();
    let a = messages.get(&large, SIG_DST);
    let b = messages.get(&large, SIG_DST);
    assert!(!Rc::ptr_eq(&a, &b));
    assert_eq!(messages.entries.len(), before);
    assert!(messages.bytes <= MAX_PREPARED_MESSAGE_BYTES);
}

#[test]
fn bounded_msms_match_independent_multiplication_at_window_and_scalar_edges() {
    let mut edge = [0; 32];
    edge[31] = 0x40; // Highest scalar bit (254), with a low window crossing.
    edge[0] = 0xf9;
    let scalars = [
        Scalar::zero(),
        Scalar::one(),
        -Scalar::one(),
        Scalar::from(31),
        Scalar::from(32),
        Scalar::from(127),
        Scalar::from_bytes(&edge).unwrap(),
    ];
    for count in [0, 1, 4, 5, 31, 32, MAX_BATCH_EQUATIONS] {
        let g1: Vec<_> = (0..count)
            .map(|index| {
                let point = if index % 5 == 0 {
                    G1Affine::identity()
                } else if index % 2 == 0 {
                    -G1Affine::generator()
                } else {
                    G1Affine::generator()
                };
                (point, scalars[index % scalars.len()])
            })
            .collect();
        let g2: Vec<_> = (0..count)
            .map(|index| {
                let point = if index % 5 == 0 {
                    G2Affine::identity()
                } else if index % 2 == 0 {
                    -G2Affine::generator()
                } else {
                    G2Affine::generator()
                };
                (point, scalars[index % scalars.len()])
            })
            .collect();
        let expected_g1 = g1
            .iter()
            .fold(G1Projective::identity(), |sum, (point, scalar)| {
                sum + point * scalar
            });
        let expected_g2 = g2
            .iter()
            .fold(G2Projective::identity(), |sum, (point, scalar)| {
                sum + point * scalar
            });
        assert_eq!(msm_g1(&g1), expected_g1, "G1 {count}");
        assert_eq!(msm_g2(&g2), expected_g2, "G2 {count}");
    }
}

#[test]
fn checked_keys_are_reused_across_bounded_batches_and_domains() {
    let sk = SecretKey::key_gen(&[8; 32], &[]).unwrap();
    let key = sk.public_key().to_bytes();
    let mut batch = BatchVerifier::default();
    for index in 0_u64..130 {
        let message = index.to_le_bytes();
        let signature = sk.sign(&message).to_bytes();
        assert!(batch.verify(&key, &message, &signature));
        // Exact repeated equations add no work, including after a flush.
        assert!(batch.verify(&key, &message, &signature));
    }
    assert_eq!(batch.equations.len(), 2);
    assert_eq!(batch.seen.len(), 130);
    assert_eq!(batch.keys.points.len(), 1);
    assert!(batch.pop(&key, &sk.prove_possession().to_bytes()));
    assert!(batch.finish());
    let mut wrong = BatchVerifier::default();
    assert!(wrong.verify(&key, &key, &sk.prove_possession().to_bytes()));
    assert!(!wrong.finish());
}

#[test]
fn retained_encodings_match_recompressed_points() {
    let first = SecretKey::key_gen(&[11; 32], &[]).unwrap();
    let second = SecretKey::key_gen(&[12; 32], &[]).unwrap();
    let keys = [
        first.public_key().to_bytes(),
        second.public_key().to_bytes(),
    ];
    let mut batch = BatchVerifier::default();
    for message in [b"first".as_slice(), b"second"] {
        assert!(batch.verify(&keys[0], message, &first.sign(message).to_bytes()));
    }
    let signatures = [first.sign(b"third"), second.sign(b"third")];
    let aggregate = aggregate_signatures(&[&signatures[0], &signatures[1]]).unwrap();
    assert!(batch.aggregate(&keys, b"third", &aggregate.to_bytes()));
    assert_eq!(batch.equations.len(), 3);
    for equation in &batch.equations {
        assert_eq!(equation.key_bytes, equation.key.to_compressed());
        assert_eq!(equation.signature_bytes, equation.signature.to_compressed());
    }
    assert!(batch.finish());
}

#[test]
fn rejects_cancelling_signature_errors_and_wrong_messages() {
    let sk = SecretKey::key_gen(&[9; 32], &[]).unwrap();
    let key = sk.public_key().to_bytes();
    let sig = G2Affine::from_compressed(&sk.sign(b"same vote").to_bytes()).unwrap();
    let delta = G2Projective::generator();
    let a = G2Affine::from(G2Projective::from(sig) + delta).to_compressed();
    let b = G2Affine::from(G2Projective::from(sig) - delta).to_compressed();
    // Their unweighted sum is exactly two valid signatures. Each is invalid.
    assert!(!verify(&key, b"same vote", &a));
    assert!(!verify(&key, b"same vote", &b));
    let mut batch = BatchVerifier::default();
    assert!(batch.verify(&key, b"same vote", &a));
    assert!(batch.verify(&key, b"same vote", &b));
    assert!(!batch.finish());
    let mut batch = BatchVerifier::default();
    assert!(batch.verify(&key, b"other vote", &sig.to_compressed()));
    assert!(!batch.finish());
}

#[test]
fn malformed_points_and_identity_aggregates_fail_closed() {
    let sk = SecretKey::key_gen(&[10; 32], &[]).unwrap();
    let key = sk.public_key().to_bytes();
    let neg = (-G1Affine::from_compressed(&key).unwrap()).to_compressed();
    let sig = sk.sign(b"vote").to_bytes();
    let mut batch = BatchVerifier::default();
    assert!(!batch.aggregate(&[key, neg], b"vote", &sig));
    assert!(!batch.finish());
    let mut batch = BatchVerifier::default();
    assert!(!batch.verify(&key, b"vote", &G2Affine::identity().to_compressed()));
    assert!(!batch.finish());
    let mut batch = BatchVerifier::default();
    assert!(!batch.verify(&[0; 48], b"vote", &sig));
    assert!(!batch.finish());
}
