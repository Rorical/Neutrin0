//! Bounded Fiat-Shamir batch verification of positive signature obligations.

use alloc::{rc::Rc, vec, vec::Vec};
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar, multi_miller_loop,
};
use neutrin0_primitives::{BlsPublicKey, BlsSignature};

use super::caches::{CheckedKeys, CheckedSignatures, PreparedMessages};
use super::{POP_DST, SIG_DST, Verifier, verify_cached_points};

pub(super) struct Equation {
    pub(super) key: G1Affine,
    /// `key.to_compressed()`, encoded once for the equation id and transcript.
    pub(super) key_bytes: BlsPublicKey,
    message: alloc::vec::Vec<u8>,
    pub(super) signature: G2Affine,
    /// Accepted compressed bytes of `signature`. Checked decompression admits
    /// only the canonical encoding, so they equal `signature.to_compressed()`.
    pub(super) signature_bytes: BlsSignature,
    dst: &'static [u8],
}

pub(super) const MAX_BATCH_EQUATIONS: usize = 64;
const SCALAR_BITS: usize = 255;

const fn msm_window(count: usize) -> usize {
    if count < 32 { 3 } else { 5 }
}

fn scalar_digit(bytes: &[u8; 32], start: usize, width: usize) -> usize {
    (start..(start + width).min(SCALAR_BITS)).fold(0, |value, bit| {
        value | (usize::from((bytes[bit / 8] >> (bit % 8)) & 1) << (bit - start))
    })
}

// Variable-time bucket selection is safe here: both the points and the full-field
// Fiat-Shamir coefficients are public proof inputs. Each MSM is bounded by the
// 64-equation flush, with at most 32 buckets and 255 scalar bits.
#[cfg(target_os = "zkvm")]
pub(super) fn msm_g1(points: &[(G1Affine, Scalar)]) -> G1Projective {
    assert!(points.len() <= MAX_BATCH_EQUATIONS);
    if points.is_empty() {
        return G1Projective::identity();
    }
    let width = msm_window(points.len());
    let scalars: Vec<_> = points.iter().map(|(_, scalar)| scalar.to_bytes()).collect();
    let mut result = G1Affine::identity();
    let mut buckets = vec![G1Affine::identity(); 1 << width];
    // These checked affine operations reach the existing SP1 G1 ADD/DOUBLE
    // circuits; the official patch handles identity, equal and inverse points.
    for window in (0..SCALAR_BITS.div_ceil(width)).rev() {
        for _ in 0..width {
            result = result.double();
        }
        buckets.fill(G1Affine::identity());
        for ((point, _), scalar) in points.iter().zip(&scalars) {
            let digit = scalar_digit(scalar, window * width, width);
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
    G1Projective::from(result)
}

#[cfg(not(target_os = "zkvm"))]
pub(super) fn msm_g1(points: &[(G1Affine, Scalar)]) -> G1Projective {
    assert!(points.len() <= MAX_BATCH_EQUATIONS);
    if points.len() <= 4 {
        return points
            .iter()
            .fold(G1Projective::identity(), |sum, (point, scalar)| {
                sum + point * scalar
            });
    }
    let width = msm_window(points.len());
    let scalars: Vec<_> = points.iter().map(|(_, scalar)| scalar.to_bytes()).collect();
    let mut result = G1Projective::identity();
    let mut buckets = vec![G1Projective::identity(); 1 << width];
    for window in (0..SCALAR_BITS.div_ceil(width)).rev() {
        for _ in 0..width {
            result = result.double();
        }
        buckets.fill(G1Projective::identity());
        for ((point, _), scalar) in points.iter().zip(&scalars) {
            let digit = scalar_digit(scalar, window * width, width);
            if digit != 0 {
                buckets[digit] += point;
            }
        }
        let mut running = G1Projective::identity();
        for bucket in buckets[1..].iter().rev() {
            running += bucket;
            result += running;
        }
    }
    result
}

pub(super) fn msm_g2(points: &[(G2Affine, Scalar)]) -> G2Projective {
    assert!(points.len() <= MAX_BATCH_EQUATIONS);
    if points.len() <= 4 {
        return points
            .iter()
            .fold(G2Projective::identity(), |sum, (point, scalar)| {
                sum + point * scalar
            });
    }
    let width = msm_window(points.len());
    let scalars: Vec<_> = points.iter().map(|(_, scalar)| scalar.to_bytes()).collect();
    let mut result = G2Projective::identity();
    let mut buckets = vec![G2Projective::identity(); 1 << width];
    // SP1 constrains G2 through the patched Fp2 arithmetic. Sharing doublings
    // across the batch does not assume a G2 curve syscall or skip validation.
    for window in (0..SCALAR_BITS.div_ceil(width)).rev() {
        for _ in 0..width {
            if !bool::from(result.is_identity()) {
                result = result.double();
            }
        }
        buckets.fill(G2Projective::identity());
        for ((point, _), scalar) in points.iter().zip(&scalars) {
            let digit = scalar_digit(scalar, window * width, width);
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
    result
}

/// Bounded Fiat-Shamir batch verifier for positive signature obligations.
///
/// Every coefficient binds every equation (key, message, signature and DST),
/// the batch length and its index. Full scalar-field coefficients prevent the
/// cancellation attack on unweighted aggregation. Subgroup checks precede all
/// batching. Equal messages share a Miller-loop term. At most 64 equations
/// are retained, and the checked-key cache survives flushes.
#[derive(Default)]
pub struct BatchVerifier {
    pub(super) keys: CheckedKeys,
    signatures: CheckedSignatures,
    messages: PreparedMessages,
    pub(super) equations: alloc::vec::Vec<Equation>,
    pub(super) seen: alloc::collections::BTreeSet<neutrin0_primitives::Hash>,
    failed: bool,
}

impl BatchVerifier {
    fn push(
        &mut self,
        key: Option<G1Affine>,
        message: &[u8],
        signature: &BlsSignature,
        dst: &'static [u8],
    ) -> bool {
        if self.failed {
            return false;
        }
        let Some(key) = key else {
            self.failed = true;
            return false;
        };
        let key_bytes = key.to_compressed();
        let id = neutrin0_consensus_types::tagged_commitment(
            b"neutrin0-bls-batch-entry",
            &(key_bytes, message, signature, dst),
        );
        if !self.seen.insert(id) {
            return !self.failed;
        }
        let signature_bytes = *signature;
        let Some(signature) = self.signatures.get(signature) else {
            self.failed = true;
            return false;
        };
        self.equations.push(Equation {
            key,
            key_bytes,
            message: message.to_vec(),
            signature,
            signature_bytes,
            dst,
        });
        if self.equations.len() == MAX_BATCH_EQUATIONS {
            self.flush();
        }
        !self.failed
    }

    fn flush(&mut self) {
        use sha2::{Digest, Sha512};
        if self.equations.is_empty() || self.failed {
            return;
        }
        if self.equations.len() == 1 {
            let equation = self.equations.pop().expect("one equation");
            self.failed = !verify_cached_points(
                equation.key,
                equation.signature,
                self.messages.get(&equation.message, equation.dst).as_ref(),
            );
            return;
        }
        let mut transcript = Sha512::new();
        transcript.update(b"neutrin0-bls-batch");
        transcript.update((self.equations.len() as u64).to_le_bytes());
        for equation in &self.equations {
            transcript.update(equation.key_bytes);
            transcript.update(equation.signature_bytes);
            transcript.update((equation.dst.len() as u64).to_le_bytes());
            transcript.update(equation.dst);
            transcript.update((equation.message.len() as u64).to_le_bytes());
            transcript.update(&equation.message);
        }
        let transcript = transcript.finalize();
        let mut groups = alloc::collections::BTreeMap::<_, Vec<_>>::new();
        let mut signatures = Vec::with_capacity(self.equations.len());
        for (index, equation) in self.equations.drain(..).enumerate() {
            let mut hash = Sha512::new();
            hash.update(b"neutrin0-bls-batch-coefficient");
            hash.update(transcript);
            hash.update((index as u64).to_le_bytes());
            let mut coefficient = Scalar::from_bytes_wide(&hash.finalize().into());
            if coefficient == Scalar::zero() {
                coefficient = Scalar::one();
            }
            signatures.push((equation.signature, coefficient));
            groups
                .entry((equation.dst, equation.message))
                .or_default()
                .push((equation.key, coefficient));
        }
        let signature = msm_g2(&signatures);
        let mut terms: alloc::vec::Vec<_> = groups
            .into_iter()
            .map(|((dst, message), keys)| {
                (
                    G1Affine::from(msm_g1(&keys)),
                    self.messages.get(&message, dst),
                )
            })
            .collect();
        terms.push((
            -G1Affine::generator(),
            Rc::new(G2Prepared::from(G2Affine::from(signature))),
        ));
        let refs: alloc::vec::Vec<_> = terms
            .iter()
            .map(|(key, point)| (key, point.as_ref()))
            .collect();
        self.failed = multi_miller_loop(&refs).final_exponentiation() != Gt::identity();
    }

    /// Verify all pending equations. No statement may be committed before this.
    #[must_use]
    pub fn finish(mut self) -> bool {
        self.flush();
        !self.failed
    }
}

impl Verifier for BatchVerifier {
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
        let key = self.keys.get(key);
        self.push(key, message, signature, SIG_DST)
    }
    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        let key = self.keys.aggregate(keys);
        self.push(key, message, signature, SIG_DST)
    }
    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
        let point = self.keys.get(key);
        self.push(point, key, signature, POP_DST)
    }
}
