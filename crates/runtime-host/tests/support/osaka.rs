//! Portable Osaka precompile inputs. P256 is REVM's upstream positive vector;
//! KZG is the EIP-4844 reference vector also used by the initial feasibility gate.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Shared fixtures of a private test support module; `pub` would be unreachable."
)]
use alloy_primitives::U256;
use neutrin0_crypto::sha256;

pub(super) fn vectors() -> Vec<(u16, Vec<u8>)> {
    let mut ecrecover = vec![0; 128];
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let (signature, recovery) = key.sign_prehash_recoverable(&[42; 32]);
    ecrecover[..32].fill(42);
    ecrecover[63] = 27 + u8::from(recovery.is_y_odd());
    ecrecover[64..].copy_from_slice(&signature.to_bytes());
    let mut modexp = vec![0; 96];
    modexp[31] = 1;
    modexp[63] = 1;
    modexp[95] = 1;
    modexp.extend([2, 5, 13]);
    let mut bn_add = vec![0; 128];
    bn_add[31] = 1;
    bn_add[63] = 2;
    bn_add[95] = 1;
    bn_add[127] = 2;
    let mut bn_mul = vec![0; 96];
    bn_mul[31] = 1;
    bn_mul[63] = 2;
    bn_mul[95] = 2;
    let bn_pair = hex::decode("1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa").unwrap();
    let mut blake = vec![0; 213];
    blake[3] = 12;
    blake[212] = 1;
    let commitment = hex::decode("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7").unwrap();
    let mut versioned = sha256(&commitment);
    versioned[0] = 1;
    let mut kzg = versioned.to_vec();
    kzg.extend(
        hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000").unwrap(),
    );
    kzg.extend(
        hex::decode("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9").unwrap(),
    );
    kzg.extend(commitment);
    kzg.extend(hex::decode("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c").unwrap());
    let g1 = revm::precompile::bls12_381::map_fp_to_g1::map_fp_to_g1(&[0; 64], 100_000)
        .unwrap()
        .bytes
        .to_vec();
    let g2 = revm::precompile::bls12_381::map_fp2_to_g2::map_fp2_to_g2(&[0; 128], 100_000)
        .unwrap()
        .bytes
        .to_vec();
    let mut g1_msm = g1.clone();
    g1_msm.extend(U256::from(2).to_be_bytes::<32>());
    let mut g2_msm = g2.clone();
    g2_msm.extend(U256::from(2).to_be_bytes::<32>());
    let mut pairing = g1.clone();
    pairing.extend(&g2);
    let p256=hex::decode("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e").unwrap();
    vec![
        (1, ecrecover),
        (2, b"abc".to_vec()),
        (3, b"abc".to_vec()),
        (4, b"abc".to_vec()),
        (5, modexp),
        (6, bn_add),
        (7, bn_mul),
        (8, bn_pair),
        (9, blake),
        (10, kzg),
        (11, [g1.clone(), g1].concat()),
        (12, g1_msm),
        (13, [g2.clone(), g2].concat()),
        (14, g2_msm),
        (15, pairing),
        (16, vec![0; 64]),
        (17, vec![0; 128]),
        (256, p256),
    ]
}

/// Cases which must retain their exact success/failure behavior under acceleration.
#[allow(
    dead_code,
    clippy::too_many_lines,
    reason = "Shared by the arithmetic gate; other gates include this module for its positive vectors. One named list captures canonical-encoding/subgroup boundaries."
)]
pub(super) fn arithmetic_adversarial_vectors() -> Vec<(&'static str, u16, Vec<u8>, bool)> {
    fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        for length in [base.len(), exp.len(), modulus.len()] {
            result.extend(U256::from(length).to_be_bytes::<32>());
        }
        result.extend(base);
        result.extend(exp);
        result.extend(modulus);
        result
    }
    let mut cases = vec![
        ("modexp-even", 5, modexp(&[7], &[23], &[16]), true),
        ("modexp-zero", 5, modexp(&[7], &[23], &[0]), true),
        ("modexp-one", 5, modexp(&[7], &[23], &[1]), true),
        ("modexp-zero-exponent", 5, modexp(&[7], &[], &[13]), true),
        ("modexp-zero-base", 5, modexp(&[], &[23], &[13]), true),
        ("modexp-zero-to-zero", 5, modexp(&[], &[], &[13]), true),
        (
            "modexp-large-exponent",
            5,
            modexp(&[7], &[0xa5; 33], &[16]),
            true,
        ),
    ];
    let mut wide = vec![0; 33];
    wide[0] = 1;
    wide[32] = 13;
    cases.push(("modexp-wide-fallback", 5, modexp(&wide, &[2], &wide), true));
    let mut padded_base = vec![0; 512];
    padded_base[511] = 7;
    let mut padded_modulus = vec![0; 512];
    padded_modulus[511] = 13;
    cases.push((
        "modexp-padded-small-factors",
        5,
        modexp(&padded_base, &[23], &padded_modulus),
        true,
    ));
    // EIP-7823 bounds every operand at 1024 bytes (8192 bits).
    let mut maximum = vec![0; 1024];
    maximum[0] = 1;
    maximum[1023] = 13;
    cases.push((
        "modexp-maximum-operand",
        5,
        modexp(&[7], &[1], &maximum),
        true,
    ));
    let mut excessive = vec![0; 96];
    excessive[64..].copy_from_slice(&U256::from(1025).to_be_bytes::<32>());
    cases.push(("modexp-reject-over-limit", 5, excessive, false));

    let mut torsion_g1 = vec![0; 128];
    torsion_g1[127] = 2; // (0,2) lies on y²=x³+4 and has order three.
    let mut torsion_g1_msm = torsion_g1.clone();
    torsion_g1_msm.extend([0; 32]);
    cases.push((
        "g1-add-nonsubgroup-allowed",
        11,
        [torsion_g1.clone(), vec![0; 128]].concat(),
        true,
    ));
    cases.push(("g1-msm-zero-scalar-nonsubgroup", 12, torsion_g1_msm, false));
    cases.push((
        "pairing-nonsubgroup-g1-with-infinity-g2",
        15,
        [torsion_g1, vec![0; 256]].concat(),
        false,
    ));

    // Canonical Ethereum c0,c1 coordinates converted from the upstream BLS
    // test_clear_cofactor fixture's Montgomery/projective limbs at immutable commit
    // c6a3a331f8bee02913cc2c4eae2805360f888aaa/src/g2.rs.
    let torsion_g2 = hex::decode(include_str!("bls-g2-nonsubgroup.hex").trim()).unwrap();
    let mut torsion_g2_msm = torsion_g2.clone();
    torsion_g2_msm.extend([0; 32]);
    cases.push((
        "g2-add-nonsubgroup-allowed",
        13,
        [torsion_g2.clone(), vec![0; 256]].concat(),
        true,
    ));
    cases.push(("g2-msm-zero-scalar-nonsubgroup", 14, torsion_g2_msm, false));
    cases.push((
        "pairing-infinity-g1-with-nonsubgroup-g2",
        15,
        [vec![0; 128], torsion_g2].concat(),
        false,
    ));
    let mut invalid_g1 = vec![0; 128];
    invalid_g1[63] = 1; // (1,1) is not on the curve.
    invalid_g1[127] = 1;
    cases.push((
        "g1-add-off-curve",
        11,
        [invalid_g1, vec![0; 128]].concat(),
        false,
    ));
    let mut flagged_g1 = vec![0; 256];
    flagged_g1[16] = 0x80; // Never permit a BLS decoder to mask EVM coordinate flags.
    cases.push(("g1-noncanonical-field-flags", 11, flagged_g1, false));
    let mut padded_g2 = vec![0; 512];
    padded_g2[64] = 1;
    cases.push(("g2-invalid-padding", 13, padded_g2, false));
    cases.push(("g1-msm-infinity", 12, vec![0; 160], true));
    cases.push(("g2-msm-infinity", 14, vec![0; 288], true));
    cases.push(("pairing-both-infinity", 15, vec![0; 384], true));

    let positive = vectors();
    for id in [12, 14] {
        let (_, single) = positive
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .unwrap();
        let point = &single[..single.len() - 32];
        cases.push((
            "msm-noncanonical-scalar-reduced",
            id,
            [point.to_vec(), vec![0xff; 32]].concat(),
            true,
        ));
        let unit = [point.to_vec(), U256::from(1).to_be_bytes::<32>().to_vec()].concat();
        cases.push(("msm-shared-window-33", id, unit.repeat(33), true));
        cases.push(("msm-shared-window-129", id, unit.repeat(129), true));
    }
    let mut fp = vec![0; 64];
    fp[63] = 1;
    cases.push(("map-canonical-fp", 16, fp, true));
    let mut fp2 = vec![0; 128];
    fp2[63] = 1;
    fp2[127] = 2;
    cases.push(("map-canonical-fp2-distinct-components", 17, fp2, true));
    let mut invalid_fp = vec![0; 64];
    invalid_fp[16..].fill(0xff);
    cases.push(("map-noncanonical-fp", 16, invalid_fp, false));
    let (_, kzg) = positive.iter().find(|(id, _)| *id == 10).unwrap();
    let mut invalid_scalar = kzg.clone();
    invalid_scalar[32..64].fill(0xff);
    cases.push(("kzg-noncanonical-scalar", 10, invalid_scalar, false));
    let mut invalid_commitment = kzg.clone();
    invalid_commitment[96..144].fill(0);
    let mut versioned = sha256(&invalid_commitment[96..144]);
    versioned[0] = 1;
    invalid_commitment[..32].copy_from_slice(&versioned);
    cases.push((
        "kzg-invalid-compressed-point",
        10,
        invalid_commitment,
        false,
    ));
    let mut torsion_commitment = kzg.clone();
    torsion_commitment[96..144].fill(0);
    torsion_commitment[96] = 0x80; // Compressed (0,2), valid curve but order three.
    let mut versioned = sha256(&torsion_commitment[96..144]);
    versioned[0] = 1;
    torsion_commitment[..32].copy_from_slice(&versioned);
    cases.push(("kzg-nonsubgroup-commitment", 10, torsion_commitment, false));
    let mut infinity_kzg = vec![0; 192];
    infinity_kzg[96] = 0xc0;
    infinity_kzg[144] = 0xc0;
    let mut versioned = sha256(&infinity_kzg[96..144]);
    versioned[0] = 1;
    infinity_kzg[..32].copy_from_slice(&versioned);
    cases.push(("kzg-infinity-zero-polynomial", 10, infinity_kzg, true));
    let mut invalid_proof = kzg.clone();
    invalid_proof[144..].fill(0xff);
    cases.push(("kzg-invalid-proof", 10, invalid_proof, false));
    let mut invalid_version = kzg.clone();
    invalid_version[0] ^= 1;
    cases.push(("kzg-version-hash", 10, invalid_version, false));
    for id in [6, 7, 8] {
        let length = match id {
            6 => 128,
            7 => 96,
            _ => 192,
        };
        let mut invalid = vec![0; length];
        invalid[..32].fill(0xff);
        cases.push(("bn254-noncanonical-field", id, invalid, false));
    }
    cases
}
