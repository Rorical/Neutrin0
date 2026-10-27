//! BN254 point decoding and encoding over the patched substrate backend.

use revm::precompile::PrecompileHalt;
use substrate_bn::{self as bn, Group as _};

// Match REVM 43.0.3's maintained substrate backend without enabling its global
// `bn` feature. This keeps native/WASM on their Arkworks backend even when the
// host workspace uses --all-features.
fn read_bn_fq(bytes: &[u8]) -> Result<bn::Fq, PrecompileHalt> {
    bn::Fq::from_slice(bytes).map_err(|_| PrecompileHalt::Bn254FieldPointNotAMember)
}

pub(super) fn read_bn_g1(bytes: &[u8]) -> Result<bn::G1, PrecompileHalt> {
    let bytes = bytes
        .get(..64)
        .ok_or(PrecompileHalt::Bn254AffineGFailedToCreate)?;
    let x = read_bn_fq(&bytes[..32])?;
    let y = read_bn_fq(&bytes[32..])?;
    if x == bn::Fq::zero() && y == bn::Fq::zero() {
        Ok(bn::G1::zero())
    } else {
        bn::AffineG1::new(x, y)
            .map(Into::into)
            .map_err(|_| PrecompileHalt::Bn254AffineGFailedToCreate)
    }
}

pub(super) fn read_bn_g2(bytes: &[u8]) -> Result<bn::G2, PrecompileHalt> {
    let bytes = bytes
        .get(..128)
        .ok_or(PrecompileHalt::Bn254AffineGFailedToCreate)?;
    // Ethereum BN254 writes the imaginary component before the real component.
    let x = bn::Fq2::new(read_bn_fq(&bytes[32..64])?, read_bn_fq(&bytes[..32])?);
    let y = bn::Fq2::new(read_bn_fq(&bytes[96..])?, read_bn_fq(&bytes[64..96])?);
    if x.is_zero() && y.is_zero() {
        Ok(bn::G2::zero())
    } else {
        // The maintained checked constructor enforces both curve and subgroup.
        bn::AffineG2::new(x, y)
            .map(Into::into)
            .map_err(|_| PrecompileHalt::Bn254AffineGFailedToCreate)
    }
}

pub(super) fn encode_bn_g1(point: bn::G1) -> [u8; 64] {
    let mut output = [0; 64];
    if let Some(point) = bn::AffineG1::from_jacobian(point) {
        point
            .x()
            .to_big_endian(&mut output[..32])
            .expect("BN254 Fq fits 32 bytes");
        point
            .y()
            .to_big_endian(&mut output[32..])
            .expect("BN254 Fq fits 32 bytes");
    }
    output
}
