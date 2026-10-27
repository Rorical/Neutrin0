//! Deterministic compressed-proof verifier for objective rejection evidence.
//!
//! Recursion syscalls can only assert acceptance. Slashing for rejection must
//! instead run the verifier as a program, over the exact signed artifact.
//! This module is shared by native callers and the guest; errors classify the
//! artifact, while a verifier panic/resource failure cannot establish rejection.

use crate::receipt_codec;
use alloc::{string::String, vec::Vec};
use core::borrow::Borrow;
use neutrin0_consensus_types::{BlockProof, ProofRejectionReason};
use neutrin0_runtime_abi::BlockReceiptStatement;
use serde::{Deserialize, Serialize};
use sp1_primitives::io::SP1PublicValues;
use sp1_recursion_executor::RecursionPublicValues;
use sp1_verifier::{SP1Proof, compressed::SP1CompressedVerifier};

/// Maximum block proof envelope payload, matching the block-proof gossip cap.
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
/// Circuit version embedded by the pinned SP1 SDK 6.10.0 (not its crate version).
pub const CIRCUIT_VERSION: &str = "v6.1.0";

/// Verify an evidence receipt under an externally authenticated program key.
/// Exact public values, success exit status and canonical codec are mandatory.
pub fn verify_evidence_receipt(
    bytes: &[u8],
    statement: &neutrin0_consensus_types::evidence::EvidenceBatch,
    key: &[u32; 8],
) -> Result<(), ProofRejectionReason> {
    decode_verified_evidence_receipt(bytes, statement, key).map(|_| ())
}

/// Decode and verify an evidence receipt once, retaining its authenticated proof
/// for the host's recursive proof stream.
pub fn decode_verified_evidence_receipt(
    bytes: &[u8],
    statement: &neutrin0_consensus_types::evidence::EvidenceBatch,
    key: &[u32; 8],
) -> Result<SP1Proof, ProofRejectionReason> {
    use neutrin0_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES;
    if bytes.len() > MAX_EVIDENCE_PROOF_BYTES {
        return Err(ProofRejectionReason::MalformedProof);
    }
    let bundle = decode_bundle::<MAX_EVIDENCE_PROOF_BYTES>(bytes)?;
    verify_typed_receipt(
        &bundle.proof,
        bundle.public_values.as_slice(),
        &bundle.sp1_version,
        statement,
        key,
    )?;
    Ok(bundle.proof)
}

/// Verify an already decoded receipt, retaining every envelope and exit check.
/// Generation paths use this before serializing, avoiding a second decoding pass.
pub fn verify_typed_receipt<T: borsh::BorshSerialize>(
    proof: &SP1Proof,
    public_values: &[u8],
    version: &str,
    expected: &T,
    key: &[u32; 8],
) -> Result<(), ProofRejectionReason> {
    let SP1Proof::Compressed(inner) = proof else {
        return Err(ProofRejectionReason::MalformedProof);
    };
    if version != CIRCUIT_VERSION
        || inner.proof.public_values.len() != sp1_hypercube::PROOF_MAX_NUM_PVS
        || public_values != borsh::to_vec(expected).expect("canonical public values")
    {
        return Err(ProofRejectionReason::PublicInputsMismatch);
    }
    let values: &RecursionPublicValues<sp1_primitives::SP1Field> =
        inner.proof.public_values.as_slice().borrow();
    if values.exit_code != sp1_primitives::SP1Field::default() {
        return Err(ProofRejectionReason::VerifierRejected);
    }
    verify_compressed(proof, public_values, key)
}

// Exact SDK 6.10.0 wire fields. Keeping the SDK host/prover itself out of the
// guest avoids a dependency on native proving services. Parity is tested with
// bundles produced by the SDK, not by a second hand-written serializer.
#[derive(Deserialize, Serialize)]
struct ProofBundle {
    proof: SP1Proof,
    public_values: SP1PublicValues,
    sp1_version: String,
    tee_proof: Option<Vec<u8>>,
}

/// Decode the one accepted encoding of a receipt, as the host does: no TEE
/// attestation (verification ignores it) and exactly the canonical bytes
/// (release builds decode a field element from any `u32` modulo `P`). Other
/// encodings of a valid proof are malformed here and on every host, so a
/// signed acceptance of one is objectively provable.
fn decode_bundle<const LIMIT: usize>(bytes: &[u8]) -> Result<ProofBundle, ProofRejectionReason> {
    let bundle: ProofBundle = receipt_codec::decode_canonical::<_, LIMIT>(bytes)
        .map_err(|_| ProofRejectionReason::MalformedProof)?;
    if bundle.tee_proof.is_some() {
        return Err(ProofRejectionReason::MalformedProof);
    }
    Ok(bundle)
}

/// Verify a signed block-proof envelope under the authenticated program key.
///
/// An `Err` is objective rejection; an execution failure/panic must never be
/// converted to `Err` by a caller. Runtime/chain/header bindings are checked
/// separately against authenticated history by the caller.
#[allow(clippy::suspicious_operation_groupings)] // STF and wire use different field names.
pub fn verify_block_artifact(
    proof: &BlockProof,
    block_guest_vk_digest: &[u32; 8],
) -> Result<(), ProofRejectionReason> {
    if proof.height != proof.public_inputs.height
        || proof.block_hash != proof.public_inputs.block_hash
    {
        return Err(ProofRejectionReason::PublicInputsMismatch);
    }
    if proof.proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(ProofRejectionReason::MalformedProof);
    }
    // Sp1BlockProof is a borsh struct containing one Vec<u8> field: a u32
    // length prefix that must equal the remaining byte count exactly.
    let Some((length, bytes)) = proof.proof_bytes.split_first_chunk::<4>() else {
        return Err(ProofRejectionReason::MalformedProof);
    };
    if usize::try_from(u32::from_le_bytes(*length)) != Ok(bytes.len()) {
        return Err(ProofRejectionReason::MalformedProof);
    }
    let bundle = decode_bundle::<MAX_PROOF_BYTES>(bytes)?;
    let SP1Proof::Compressed(inner) = &bundle.proof else {
        return Err(ProofRejectionReason::MalformedProof);
    };
    if bundle.sp1_version != CIRCUIT_VERSION
        || inner.proof.public_values.len() != sp1_hypercube::PROOF_MAX_NUM_PVS
    {
        return Err(ProofRejectionReason::VerifierRejected);
    }
    let recursion_values: &RecursionPublicValues<sp1_primitives::SP1Field> =
        inner.proof.public_values.as_slice().borrow();
    if recursion_values.exit_code != sp1_primitives::SP1Field::default() {
        return Err(ProofRejectionReason::VerifierRejected);
    }
    let statement: BlockReceiptStatement = borsh::from_slice(bundle.public_values.as_slice())
        .map_err(|_| ProofRejectionReason::MalformedProof)?;
    if !crate::execution::output_binds(&statement.output, &proof.public_inputs) {
        return Err(ProofRejectionReason::PublicInputsMismatch);
    }
    verify_decoded_receipt(&bundle, block_guest_vk_digest)
}

// Keep the SDK's exact key-field decoding while passing the already decoded
// proof directly to its verifier. The large receipt is decoded once (and
// re-encoded once, for the canonical check). Envelope, exit-code and statement
// checks stay above.
fn verify_decoded_receipt(
    bundle: &ProofBundle,
    key: &[u32; 8],
) -> Result<(), ProofRejectionReason> {
    verify_compressed(&bundle.proof, bundle.public_values.as_slice(), key)
}

fn verify_compressed(
    bundle: &SP1Proof,
    public_values: &[u8],
    key: &[u32; 8],
) -> Result<(), ProofRejectionReason> {
    let SP1Proof::Compressed(proof) = bundle else {
        return Err(ProofRejectionReason::MalformedProof);
    };
    let key_bytes = receipt_codec::encode(key).expect("fixed key encoding");
    let key = receipt_codec::decode::<[sp1_primitives::SP1Field; 8], 32>(&key_bytes)
        .map_err(|_| ProofRejectionReason::VerifierRejected)?;
    SP1CompressedVerifier::new()
        .verify_compressed_with_public_values(proof, public_values, &key)
        .map_err(|_| ProofRejectionReason::VerifierRejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tee_attestation_makes_a_receipt_malformed_here_as_on_hosts() {
        let mut bundle = ProofBundle {
            proof: SP1Proof::Core(Vec::new()),
            public_values: SP1PublicValues::default(),
            sp1_version: String::new(),
            tee_proof: None,
        };
        let plain = receipt_codec::encode(&bundle).unwrap();
        assert!(decode_bundle::<1024>(&plain).is_ok());
        bundle.tee_proof = Some(alloc::vec![1]);
        let attested = receipt_codec::encode(&bundle).unwrap();
        assert!(matches!(
            decode_bundle::<1024>(&attested),
            Err(ProofRejectionReason::MalformedProof)
        ));
    }
}
