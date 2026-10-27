//! Guest-only arithmetic adapter to SP1's constrained cryptographic circuits.
//!
//! REVM retains the Osaka entrypoint parsing, input-size limits and gas schedules.
//! The official library patches constrain field/curve arithmetic; this adapter
//! additionally enforces Ethereum's canonical encodings and subgroup rules.

mod bls12_381;
mod bn254;
mod modexp;

use ::bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, hash_to_curve::MapToCurve};
use alloc::vec::Vec;
use bls12_381::{
    encode_g1, encode_g2, msm_g1, msm_g2, pairing_check, read_fp, read_g1, read_g2,
    scalar_canonical, scalar_reduced,
};
use bn254::{encode_bn_g1, read_bn_g1, read_bn_g2};
use crypto_bigint::{Encoding, U256};
use modexp::{exponentiate_u256, read_u256, significant_bytes};
use revm::precompile::{
    Crypto, DefaultCrypto, PrecompileHalt,
    bls12_381::{G1Point, G1PointScalar, G2Point, G2PointScalar},
    bls12_381_const::TRUSTED_SETUP_TAU_G2_BYTES,
};
use revm::primitives::OnceLock;
use substrate_bn::{self as bn, Group as _};

#[derive(Debug)]
struct Sp1Crypto;

/// Install once, before REVM invokes any Ethereum crypto operation.
pub(crate) fn install() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        assert!(
            revm::precompile::install_crypto(Sp1Crypto),
            "EVM Guest crypto provider was initialized before SP1 acceleration"
        );
    });
}

impl Crypto for Sp1Crypto {
    fn bn254_g1_add(&self, a: &[u8], b: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        Ok(encode_bn_g1(read_bn_g1(a)? + read_bn_g1(b)?))
    }

    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        let point = read_bn_g1(point)?;
        // Fr::from_slice reduces the full 256-bit scalar, as EIP-196 requires.
        if scalar.len() != 32 {
            return Err(PrecompileHalt::Bn254FieldPointNotAMember);
        }
        let scalar =
            bn::Fr::from_slice(scalar).map_err(|_| PrecompileHalt::Bn254FieldPointNotAMember)?;
        Ok(encode_bn_g1(point * scalar))
    }

    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        let mut parsed = Vec::with_capacity(pairs.len());
        for (g1, g2) in pairs {
            // Invalid counterparts still fail when the other point is infinity.
            let g1 = read_bn_g1(g1)?;
            let g2 = read_bn_g2(g2)?;
            if !g1.is_zero() && !g2.is_zero() {
                parsed.push((g1, g2));
            }
        }
        Ok(parsed.is_empty() || bn::pairing_batch(&parsed) == bn::Gt::one())
    }

    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        // The generic Osaka limit remains 8192 bytes per operand. Wider factors
        // use REVM's portable implementation; no input is narrowed or rejected.
        let short_base = significant_bytes(base);
        let short_modulus = significant_bytes(modulus);
        if short_base.len() > 32 || short_modulus.len() > 32 {
            return DefaultCrypto.modexp(base, exp, modulus);
        }
        // Leading zero padding does not alter the integer or its charged gas.
        // REVM pads the result back to the originally declared modulus length.
        let modulus = read_u256(short_modulus);
        if modulus == U256::ZERO || modulus == U256::ONE {
            return Ok(Vec::new());
        }
        // BIGINT accepts any nonzero modulus, including even moduli. Its safe
        // official wrapper also checks that every constrained result is reduced.
        let multiply = |a: &U256, b: &U256| crypto_bigint::succinct::modmul_u256(a, b, &modulus);
        let base = multiply(&read_u256(short_base), &U256::ONE);
        let result = exponentiate_u256(base, exp, &modulus);
        Ok(result.to_be_bytes().to_vec())
    }

    fn bls12_381_g1_add(&self, a: G1Point, b: G1Point) -> Result<[u8; 96], PrecompileHalt> {
        let a = read_g1(a, false)?;
        let b = read_g1(b, false)?;
        Ok(encode_g1(a.add_affine(&b)))
    }

    fn bls12_381_g2_add(&self, a: G2Point, b: G2Point) -> Result<[u8; 192], PrecompileHalt> {
        let a = read_g2(a, false)?;
        let b = read_g2(b, false)?;
        Ok(encode_g2(G2Affine::from(G2Projective::from(a) + b)))
    }

    fn bls12_381_g1_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<G1PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; 96], PrecompileHalt> {
        let mut points = Vec::new();
        for pair in pairs {
            let (point, scalar) = pair?;
            // Invalid points must fail even when paired with a zero scalar.
            let point = read_g1(point, true)?;
            if scalar.iter().any(|byte| *byte != 0) {
                points.push((point, scalar_reduced(&scalar)));
            }
        }
        Ok(encode_g1(msm_g1(&points)))
    }

    fn bls12_381_g2_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<G2PointScalar, PrecompileHalt>>,
    ) -> Result<[u8; 192], PrecompileHalt> {
        let mut points = Vec::new();
        for pair in pairs {
            let (point, scalar) = pair?;
            let point = read_g2(point, true)?;
            if scalar.iter().any(|byte| *byte != 0) {
                points.push((point, scalar_reduced(&scalar)));
            }
        }
        Ok(encode_g2(msm_g2(&points)))
    }

    fn bls12_381_pairing_check(
        &self,
        pairs: &[(G1Point, G2Point)],
    ) -> Result<bool, PrecompileHalt> {
        let mut parsed = Vec::with_capacity(pairs.len());
        for (g1, g2) in pairs {
            // Both points are validated before an infinity pair is skipped.
            let g1 = read_g1(*g1, true)?;
            let g2 = read_g2(*g2, true)?;
            if !bool::from(g1.is_identity() | g2.is_identity()) {
                parsed.push((g1, g2));
            }
        }
        Ok(parsed.is_empty() || pairing_check(&parsed))
    }

    fn bls12_381_fp_to_g1(&self, fp: &[u8; 48]) -> Result<[u8; 96], PrecompileHalt> {
        let mapped = G1Projective::map_to_curve(&read_fp(fp)?).clear_h();
        Ok(encode_g1(G1Affine::from(mapped)))
    }

    // MAP_FP2_TO_G2 keeps REVM's reference implementation, which producers
    // run in WASM: the accelerated library maps the zero element to the
    // identity where EIP-2537 requires a curve point, so a receipt for a block
    // calling it would contradict the honest header.

    fn verify_kzg_proof(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), PrecompileHalt> {
        let invalid = PrecompileHalt::BlobVerifyKzgProofFailed;
        let commitment = Option::<G1Affine>::from(G1Affine::from_compressed(commitment))
            .ok_or_else(|| invalid.clone())?;
        let proof = Option::<G1Affine>::from(G1Affine::from_compressed(proof))
            .ok_or_else(|| invalid.clone())?;
        let z = scalar_canonical(z).ok_or_else(|| invalid.clone())?;
        let y = scalar_canonical(y).ok_or_else(|| invalid.clone())?;
        static TAU: OnceLock<G2Affine> = OnceLock::new();
        let tau = TAU.get_or_init(|| {
            Option::<G2Affine>::from(G2Affine::from_compressed(&TRUSTED_SETUP_TAU_G2_BYTES))
                .expect("Ethereum ceremony G2 point is canonical and in the subgroup")
        });
        let p_minus_y = commitment.add_affine(&-msm_g1(&[(G1Affine::generator(), y)]));
        let x_minus_z = G2Projective::from(*tau) - msm_g2(&[(G2Affine::generator(), z)]);
        if pairing_check(&[
            (p_minus_y, -G2Affine::generator()),
            (proof, G2Affine::from(x_minus_z)),
        ]) {
            Ok(())
        } else {
            Err(invalid)
        }
    }
}
