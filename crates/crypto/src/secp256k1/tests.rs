use super::*;
use getrandom::SysRng;
use rand_core::UnwrapErr;

#[test]
fn ethereum_address_matches_the_scalar_one_reference() {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = SecretKey::from_bytes(&scalar).unwrap();
    assert_eq!(
        hex::encode(key.public_key().ethereum_address()),
        "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
}

#[test]
fn keygen_sign_verify_roundtrips() {
    let sk = SecretKey::generate(&mut UnwrapErr(SysRng));
    let pk = sk.public_key();
    let msg = b"hello, neutrin0";
    let sig = sk.sign(msg);
    pk.verify(msg, &sig).expect("verify");
}

#[test]
fn recovery_returns_signer_pubkey() {
    let sk = SecretKey::generate(&mut UnwrapErr(SysRng));
    let pk = sk.public_key();
    let msg = b"message to recover from";
    let sig = sk.sign(msg);
    let recovered = recover(msg, &sig).expect("recover");
    assert_eq!(recovered.to_bytes(), pk.to_bytes());
}

#[test]
fn verify_fails_on_tampered_message() {
    let sk = SecretKey::generate(&mut UnwrapErr(SysRng));
    let pk = sk.public_key();
    let sig = sk.sign(b"original");
    assert_eq!(pk.verify(b"tampered", &sig), Err(CryptoError::Verification));
}

#[test]
fn verify_rejects_invalid_recovery_id() {
    let sk = SecretKey::generate(&mut UnwrapErr(SysRng));
    let pk = sk.public_key();
    let msg = b"recoverable signature";
    let mut sig = sk.sign(msg);
    sig[64] = 4;
    assert_eq!(pk.verify(msg, &sig), Err(CryptoError::InvalidSignature));
    assert_eq!(recover(msg, &sig), Err(CryptoError::InvalidSignature));
}

#[test]
fn verify_fails_on_wrong_pubkey() {
    let sk1 = SecretKey::generate(&mut UnwrapErr(SysRng));
    let sk2 = SecretKey::generate(&mut UnwrapErr(SysRng));
    let msg = b"msg";
    let sig = sk1.sign(msg);
    assert_eq!(
        sk2.public_key().verify(msg, &sig),
        Err(CryptoError::Verification)
    );
}

#[test]
fn from_bytes_rejects_zero_scalar() {
    let zero = [0_u8; 32];
    assert!(matches!(
        SecretKey::from_bytes(&zero),
        Err(CryptoError::InvalidSecretKey)
    ));
}

#[test]
fn from_bytes_rejects_group_order_scalar() {
    // n = group order of secp256k1
    let n_bytes = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        .expect("hex");
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&n_bytes);
    assert!(matches!(
        SecretKey::from_bytes(&bytes),
        Err(CryptoError::InvalidSecretKey)
    ));
}

#[test]
fn pubkey_roundtrips_bytes() {
    let sk = SecretKey::generate(&mut UnwrapErr(SysRng));
    let pk1 = sk.public_key();
    let pk2 = PublicKey::from_bytes(&pk1.to_bytes()).expect("valid");
    assert_eq!(pk1.to_bytes(), pk2.to_bytes());
}

#[test]
fn secret_key_roundtrips_bytes() {
    let sk1 = SecretKey::generate(&mut UnwrapErr(SysRng));
    let bytes = sk1.to_bytes();
    let sk2 = SecretKey::from_bytes(&bytes).expect("valid");
    assert_eq!(sk1.public_key().to_bytes(), sk2.public_key().to_bytes());
}

#[test]
fn signature_is_low_s_normalised() {
    // BIP-62 normalisation: s <= n/2.
    let sk = SecretKey::from_bytes(&[1_u8; 32]).expect("valid");
    let sig = sk.sign(b"deterministic message");
    let half_order =
        hex::decode("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
            .expect("hex");
    assert!(sig[32..64] <= half_order[..]);
}

#[test]
fn sign_is_deterministic_for_same_key_and_message() {
    let sk = SecretKey::from_bytes(&[2_u8; 32]).expect("valid");
    assert_eq!(sk.sign(b"same message"), sk.sign(b"same message"));
}

#[test]
fn verify_rejects_high_s_malleated_signature() {
    let sk = SecretKey::from_bytes(&[3_u8; 32]).expect("valid");
    let pk = sk.public_key();
    let msg = b"high-s malleability";
    let mut sig = sk.sign(msg);

    let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        .expect("hex");
    let high_s = subtract_be(&order, &sig[32..64]);
    sig[32..64].copy_from_slice(&high_s);

    assert_eq!(pk.verify(msg, &sig), Err(CryptoError::Verification));
}

#[test]
fn secret_key_debug_does_not_leak_scalar() {
    let scalar = [4_u8; 32];
    let sk = SecretKey::from_bytes(&scalar).expect("valid");
    let debug = format!("{sk:?}");
    assert!(!debug.contains(&hex::encode(scalar)));
    assert!(debug.contains("pubkey"));
}

fn subtract_be(lhs: &[u8], rhs: &[u8]) -> [u8; 32] {
    debug_assert_eq!(lhs.len(), 32);
    debug_assert_eq!(rhs.len(), 32);
    let mut out = [0_u8; 32];
    let mut borrow = 0_u16;
    for i in (0..32).rev() {
        let left = u16::from(lhs[i]);
        let right = u16::from(rhs[i]) + borrow;
        if left >= right {
            out[i] = u8::try_from(left - right).expect("difference fits in u8");
            borrow = 0;
        } else {
            out[i] = u8::try_from(left + 256 - right).expect("difference fits in u8");
            borrow = 1;
        }
    }
    debug_assert_eq!(borrow, 0);
    out
}
