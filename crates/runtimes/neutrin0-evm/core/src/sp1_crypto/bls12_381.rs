//! BLS12-381 decoding, encoding, multi-scalar multiplication and pairing over
//! the patched curve library.

use alloc::{vec, vec::Vec};
use bls12_381::{
    G1Affine, G2Affine, G2Prepared, G2Projective, Gt, Scalar, fp::Fp, multi_miller_loop,
};
use revm::precompile::{
    PrecompileHalt,
    bls12_381::{G1Point, G2Point},
};

pub(super) fn read_fp(bytes: &[u8; 48]) -> Result<Fp, PrecompileHalt> {
    Option::<Fp>::from(Fp::from_bytes(bytes)).ok_or(PrecompileHalt::NonCanonicalFp)
}

pub(super) fn read_g1(point: G1Point, subgroup: bool) -> Result<G1Affine, PrecompileHalt> {
    let (x, y) = point;
    let px = read_fp(&x)?;
    let py = read_fp(&y)?;
    if bool::from(px.is_zero() & py.is_zero()) {
        return Ok(G1Affine::identity());
    }
    let mut bytes = [0; 96];
    bytes[..48].copy_from_slice(&x);
    bytes[48..].copy_from_slice(&y);
    // Canonical fields were checked before this decoder can mask flag bits.
    // G1ADD intentionally accepts non-subgroup points, but always checks the curve.
    let point = Option::<G1Affine>::from(G1Affine::from_uncompressed_unchecked(&bytes))
        .ok_or(PrecompileHalt::Bls12381G1NotOnCurve)?;
    if !bool::from(point.is_on_curve()) {
        return Err(PrecompileHalt::Bls12381G1NotOnCurve);
    }
    if subgroup && !bool::from(point.is_torsion_free()) {
        return Err(PrecompileHalt::Bls12381G1NotInSubgroup);
    }
    Ok(point)
}

pub(super) fn read_g2(point: G2Point, subgroup: bool) -> Result<G2Affine, PrecompileHalt> {
    let (x0, x1, y0, y1) = point;
    let fields = [read_fp(&x0)?, read_fp(&x1)?, read_fp(&y0)?, read_fp(&y1)?];
    if fields.iter().all(|field| bool::from(field.is_zero())) {
        return Ok(G2Affine::identity());
    }
    // Ethereum uses c0,c1; the BLS serialization uses c1,c0 for each Fp2.
    let mut bytes = [0; 192];
    bytes[..48].copy_from_slice(&x1);
    bytes[48..96].copy_from_slice(&x0);
    bytes[96..144].copy_from_slice(&y1);
    bytes[144..].copy_from_slice(&y0);
    let point = Option::<G2Affine>::from(G2Affine::from_uncompressed_unchecked(&bytes))
        .ok_or(PrecompileHalt::Bls12381G2NotOnCurve)?;
    if !bool::from(point.is_on_curve()) {
        return Err(PrecompileHalt::Bls12381G2NotOnCurve);
    }
    if subgroup && !bool::from(point.is_torsion_free()) {
        return Err(PrecompileHalt::Bls12381G2NotInSubgroup);
    }
    Ok(point)
}

pub(super) fn encode_g1(point: G1Affine) -> [u8; 96] {
    if bool::from(point.is_identity()) {
        [0; 96]
    } else {
        point.to_uncompressed()
    }
}

pub(super) fn encode_g2(point: G2Affine) -> [u8; 192] {
    if bool::from(point.is_identity()) {
        return [0; 192];
    }
    let bytes = point.to_uncompressed();
    let mut result = [0; 192];
    result[..48].copy_from_slice(&bytes[48..96]);
    result[48..96].copy_from_slice(&bytes[..48]);
    result[96..144].copy_from_slice(&bytes[144..]);
    result[144..].copy_from_slice(&bytes[96..144]);
    result
}

pub(super) fn scalar_reduced(bytes: &[u8; 32]) -> Scalar {
    let mut wide = [0; 64];
    for (target, source) in wide[..32].iter_mut().zip(bytes.iter().rev()) {
        *target = *source;
    }
    Scalar::from_bytes_wide(&wide)
}

pub(super) fn scalar_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut little_endian = *bytes;
    little_endian.reverse();
    Scalar::from_bytes(&little_endian).into()
}

pub(super) fn pairing_check(pairs: &[(G1Affine, G2Affine)]) -> bool {
    // One combined Miller loop and final exponentiation, including for KZG.
    let prepared: Vec<_> = pairs
        .iter()
        .map(|(_, point)| G2Prepared::from(*point))
        .collect();
    let terms: Vec<_> = pairs
        .iter()
        .zip(&prepared)
        .map(|((point, _), prepared)| (point, prepared))
        .collect();
    multi_miller_loop(&terms).final_exponentiation() == Gt::identity()
}

fn window_width(count: usize) -> usize {
    match count {
        0..32 => 3,
        32..128 => 5,
        _ => 7,
    }
}

fn scalar_window(bytes: &[u8; 32], start: usize, width: usize) -> usize {
    (start..(start + width).min(255)).fold(0, |value, bit| {
        value | (usize::from((bytes[bit / 8] >> (bit % 8)) & 1) << (bit - start))
    })
}

pub(super) fn msm_g1(points: &[(G1Affine, Scalar)]) -> G1Affine {
    if points.is_empty() {
        return G1Affine::identity();
    }
    let width = window_width(points.len());
    let scalars: Vec<_> = points.iter().map(|(_, scalar)| scalar.to_bytes()).collect();
    let mut result = G1Affine::identity();
    let mut buckets = vec![G1Affine::identity(); 1 << width];
    // Variable-time Pippenger over public EVM inputs. Affine complete additions
    // reach BLS12381_ADD/DOUBLE rather than emulating projective formulas in Fp.
    for window in (0..255_usize.div_ceil(width)).rev() {
        for _ in 0..width {
            result = result.double();
        }
        buckets.fill(G1Affine::identity());
        for ((point, _), scalar) in points.iter().zip(&scalars) {
            let digit = scalar_window(scalar, window * width, width);
            if digit != 0 {
                buckets[digit] = buckets[digit].add_affine(point);
            }
        }
        let mut running = G1Affine::identity();
        for bucket in buckets[1..].iter().rev() {
            running = running.add_affine(bucket);
            result = result.add_affine(&running);
        }
    }
    result
}

pub(super) fn msm_g2(points: &[(G2Affine, Scalar)]) -> G2Affine {
    if points.is_empty() {
        return G2Affine::identity();
    }
    let width = window_width(points.len());
    let scalars: Vec<_> = points.iter().map(|(_, scalar)| scalar.to_bytes()).collect();
    let mut result = G2Projective::identity();
    let mut buckets = vec![G2Projective::identity(); 1 << width];
    // G2 arithmetic is constrained by the patched Fp2 circuits. Share doublings
    // and bucket sums across scalars rather than multiplying every point alone.
    for window in (0..255_usize.div_ceil(width)).rev() {
        for _ in 0..width {
            if !bool::from(result.is_identity()) {
                result = result.double();
            }
        }
        buckets.fill(G2Projective::identity());
        for ((point, _), scalar) in points.iter().zip(&scalars) {
            let digit = scalar_window(scalar, window * width, width);
            if digit != 0 {
                buckets[digit] += point;
            }
        }
        let mut running = G2Projective::identity();
        for bucket in buckets[1..].iter().rev() {
            if !bool::from(bucket.is_identity()) {
                running += bucket;
            }
            if !bool::from(running.is_identity()) {
                result += running;
            }
        }
    }
    G2Affine::from(result)
}
