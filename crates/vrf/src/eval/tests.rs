use super::*;

use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::BlsSignature;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn deterministic_sk(seed: u64) -> SecretKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SecretKey::generate(&mut rng)
}

const DOMAIN: ConsensusDomain = ConsensusDomain::new(0xAABB_CCDD_1234_5678, [0x35; 32]);
const SEED: Seed = [0x42; 32];
const SLOT: Slot = 17;

#[test]
fn vrf_message_has_canonical_layout() {
    let msg = vrf_message(DOMAIN, &SEED, SLOT);
    assert_eq!(msg.len(), 16 + 8 + 32 + 32 + 8);
    assert_eq!(&msg[0..16], &DOMAIN_VRF);
    assert_eq!(&msg[16..24], &DOMAIN.chain_id.to_le_bytes());
    assert_eq!(&msg[24..56], &DOMAIN.chain_spec_hash);
    assert_eq!(&msg[56..88], &SEED);
    assert_eq!(&msg[88..96], &SLOT.to_le_bytes());
}

#[test]
fn eval_is_deterministic() {
    let sk = deterministic_sk(1);
    let (p1, o1) = eval(&sk, DOMAIN, &SEED, SLOT);
    let (p2, o2) = eval(&sk, DOMAIN, &SEED, SLOT);
    assert_eq!(p1.to_bytes(), p2.to_bytes());
    assert_eq!(o1, o2);
}

#[test]
fn eval_verify_roundtrip() {
    let sk = deterministic_sk(2);
    let pk = sk.public_key();
    let (proof, output) = eval(&sk, DOMAIN, &SEED, SLOT);
    let recovered = verify(&pk, DOMAIN, &SEED, SLOT, &proof).expect("verify");
    assert_eq!(recovered, output);
}

#[test]
fn proof_roundtrips_through_wire_bytes() {
    let sk = deterministic_sk(22);
    let pk = sk.public_key();
    let (proof, output) = eval(&sk, DOMAIN, &SEED, SLOT);
    let proof_bytes: BlsSignature = proof.to_bytes();
    let reparsed = Signature::from_bytes(&proof_bytes).expect("canonical proof bytes");
    assert_eq!(
        verify(&pk, DOMAIN, &SEED, SLOT, &reparsed).expect("verify reparsed proof"),
        output
    );
}

#[test]
fn vrf_output_equals_sha256_of_proof_bytes() {
    let sk = deterministic_sk(3);
    let (proof, output) = eval(&sk, DOMAIN, &SEED, SLOT);
    assert_eq!(output, sha256(&proof.to_bytes()));
}

#[test]
fn verify_rejects_wrong_public_key() {
    let sk1 = deterministic_sk(4);
    let sk2 = deterministic_sk(5);
    let (proof, _) = eval(&sk1, DOMAIN, &SEED, SLOT);
    assert!(matches!(
        verify(&sk2.public_key(), DOMAIN, &SEED, SLOT, &proof),
        Err(CryptoError::Verification)
    ));
}

#[test]
fn verify_rejects_wrong_chain_id() {
    let sk = deterministic_sk(6);
    let (proof, _) = eval(&sk, DOMAIN, &SEED, SLOT);
    assert!(matches!(
        verify(
            &sk.public_key(),
            ConsensusDomain {
                chain_id: DOMAIN.chain_id ^ 1,
                ..DOMAIN
            },
            &SEED,
            SLOT,
            &proof
        ),
        Err(CryptoError::Verification)
    ));
}

#[test]
fn verify_rejects_another_spec_with_the_same_chain_id() {
    let sk = deterministic_sk(6);
    let (proof, _) = eval(&sk, DOMAIN, &SEED, SLOT);
    let other = ConsensusDomain {
        chain_spec_hash: [0x36; 32],
        ..DOMAIN
    };
    assert!(matches!(
        verify(&sk.public_key(), other, &SEED, SLOT, &proof),
        Err(CryptoError::Verification)
    ));
}

#[test]
fn verify_rejects_wrong_seed() {
    let sk = deterministic_sk(7);
    let (proof, _) = eval(&sk, DOMAIN, &SEED, SLOT);
    let mut tampered = SEED;
    tampered[0] ^= 0x01;
    assert!(matches!(
        verify(&sk.public_key(), DOMAIN, &tampered, SLOT, &proof),
        Err(CryptoError::Verification)
    ));
}

#[test]
fn verify_rejects_wrong_slot() {
    let sk = deterministic_sk(8);
    let (proof, _) = eval(&sk, DOMAIN, &SEED, SLOT);
    assert!(matches!(
        verify(&sk.public_key(), DOMAIN, &SEED, SLOT + 1, &proof),
        Err(CryptoError::Verification)
    ));
}

#[test]
fn verify_rejects_bit_flipped_proof() {
    let sk = deterministic_sk(9);
    let (proof, _) = eval(&sk, DOMAIN, &SEED, SLOT);
    let mut bytes = proof.to_bytes();
    // Flip a low-order bit; a single-bit change in the compressed G2
    // encoding must invalidate the signature.
    bytes[40] ^= 0x01;
    // The flip may still decode as a valid G2 point but with wrong
    // semantics; or it may fail to decode. Either path means "not the
    // signature this validator produced".
    match Signature::from_bytes(&bytes) {
        Err(_) => {}
        Ok(tampered) => assert!(matches!(
            verify(&sk.public_key(), DOMAIN, &SEED, SLOT, &tampered),
            Err(CryptoError::Verification)
        )),
    }
}

#[test]
fn different_slots_produce_different_outputs() {
    let sk = deterministic_sk(10);
    let (_, out_a) = eval(&sk, DOMAIN, &SEED, SLOT);
    let (_, out_b) = eval(&sk, DOMAIN, &SEED, SLOT + 1);
    assert_ne!(out_a, out_b);
}

#[test]
fn different_chain_ids_produce_different_outputs() {
    let sk = deterministic_sk(11);
    let (_, out_a) = eval(&sk, DOMAIN, &SEED, SLOT);
    let (_, out_b) = eval(
        &sk,
        ConsensusDomain {
            chain_id: DOMAIN.chain_id ^ 1,
            ..DOMAIN
        },
        &SEED,
        SLOT,
    );
    assert_ne!(out_a, out_b);
}

#[test]
fn different_finalized_seeds_produce_different_outputs() {
    let sk = deterministic_sk(12);
    let mut other_seed = SEED;
    other_seed[31] ^= 0x01;
    let (_, out_a) = eval(&sk, DOMAIN, &SEED, SLOT);
    let (_, out_b) = eval(&sk, DOMAIN, &other_seed, SLOT);
    assert_ne!(out_a, out_b);
}
