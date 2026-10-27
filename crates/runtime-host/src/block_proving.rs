//! Block proving and verification entry points: the Guest's stdin layout,
//! compressed proving under a supplied or env-driven prover and the
//! committed-output cross-check.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::evidence::EvidenceArtifact;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_abi::RuntimeBlockOutput;
use neutrin0_runtime_abi::StateWitness;
use sp1_sdk::{
    HashableKey, ProvingKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    blocking::{Prover, ProverClient},
};

use crate::error::codec_err;
use crate::prover_ctx::embedded_evidence_vk;
use crate::{
    EVM_GUEST_ELF, ProgramProver, Sp1HostError, evidence, guarded, prove_compressed, sdk_err,
};

/// Output of [`prove`] / [`prove_with`]: the proof, the verifying key
/// bound to the guest ELF, and the witness that produced it.
pub struct BlockProof {
    /// Compressed STARK proof and its committed public values.
    pub proof: SP1ProofWithPublicValues,
    /// Verifying key bound to the guest ELF.
    pub vk: SP1VerifyingKey,
    /// Witness handed to the guest.
    pub witness: StateWitness,
}

fn encode_stdin(
    input: &RuntimeBlockInput,
    witness: &StateWitness,
    attachments: &[EvidenceArtifact],
    prover_address: neutrin0_primitives::Hash,
) -> Result<Vec<u8>, Sp1HostError> {
    let mut bytes = crate::executor::ProvingInputWriter::new(
        input.evidence_anchor.max_block_proving_input_bytes,
    )
    .map_err(codec_err)?;
    BorshSerialize::serialize(input, &mut bytes).map_err(codec_err)?;
    BorshSerialize::serialize(witness, &mut bytes).map_err(codec_err)?;
    let memberships: Vec<_> = attachments
        .iter()
        .map(|attachment| &attachment.membership)
        .collect();
    BorshSerialize::serialize(&memberships, &mut bytes).map_err(codec_err)?;
    BorshSerialize::serialize(&prover_address, &mut bytes).map_err(codec_err)?;
    let bytes = bytes.into_bytes();
    if !input
        .evidence_anchor
        .accepts_proving_input_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
    {
        return Err(Sp1HostError::Sdk(
            "block normal stdin exceeds authenticated allocation limit".into(),
        ));
    }
    Ok(bytes)
}

// The block's normal stdin contains only STF input and state openings. Verified
// evidence attachments enter SP1's separate recursive proof stream, never the STF.
// They verify under `evidence_vk`, which must be the anchor's evidence program.
pub(super) fn block_stdin(
    input: &RuntimeBlockInput,
    witness: &StateWitness,
    evidence_proofs: &[EvidenceArtifact],
    evidence_vk: Option<&SP1VerifyingKey>,
    prover_address: neutrin0_primitives::Hash,
) -> Result<SP1Stdin, Sp1HostError> {
    let proofs = evidence::verify_input_receipts(input, evidence_proofs)?;
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(encode_stdin(
        input,
        witness,
        evidence_proofs,
        prover_address,
    )?);
    if !proofs.is_empty() {
        let Some(key) = evidence_vk else {
            return Err(Sp1HostError::Sdk(
                "evidence program verifying key unavailable".into(),
            ));
        };
        if key.hash_u32() != input.evidence_anchor.evidence_guest_vk_digest {
            return Err(Sp1HostError::Sdk(
                "evidence program identity mismatch".into(),
            ));
        }
        for proof in proofs {
            let SP1Proof::Compressed(inner) = proof else {
                return Err(Sp1HostError::Sdk(
                    "evidence proof must be compressed".into(),
                ));
            };
            stdin.write_proof(*inner, key.vk.clone());
        }
    }
    Ok(stdin)
}

/// Prove a state transition using the supplied prover. Use [`prove`]
/// for the env-driven default.
///
/// # Errors
/// Returns [`Sp1HostError::Sdk`] when proving fails, or
/// [`Sp1HostError::Codec`] when the input cannot be borsh-encoded.
pub fn prove_with<P>(
    prover: &P,
    input: &RuntimeBlockInput,
    witness: StateWitness,
    evidence_proofs: &[EvidenceArtifact],
    prover_address: neutrin0_primitives::Hash,
) -> Result<BlockProof, Sp1HostError>
where
    P: ProgramProver,
{
    let pk = prover.setup_program(EVM_GUEST_ELF.clone())?;
    let vk = pk.verifying_key().clone();

    let evidence_vk = if evidence_proofs.is_empty() {
        None
    } else {
        Some(embedded_evidence_vk(prover)?)
    };
    let stdin = block_stdin(
        input,
        &witness,
        evidence_proofs,
        evidence_vk.as_ref(),
        prover_address,
    )?;

    let proof = prove_compressed(prover, &pk, stdin).map_err(sdk_err)?;
    Ok(BlockProof { proof, vk, witness })
}

/// Verify a proof using the supplied prover and decode the committed
/// [`RuntimeBlockOutput`], returning it if it matches `expected`.
///
/// # Errors
/// - [`Sp1HostError::Sdk`] on cryptographic verification failure.
/// - [`Sp1HostError::DecodeOutput`] if the committed payload is not a
///   valid borsh-encoded `RuntimeBlockOutput`.
/// - [`Sp1HostError::PublicOutputMismatch`] if the committed output
///   does not equal `expected`.
pub fn verify_with<P>(
    prover: &P,
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    expected: &RuntimeBlockOutput,
) -> Result<(), Sp1HostError>
where
    P: Prover,
{
    guarded(|| prover.verify(proof, vk, None))
        .map_err(|_| Sp1HostError::Sdk("proof verifier panicked".into()))?
        .map_err(sdk_err)?;

    let bytes = proof.public_values.as_slice();
    let actual = neutrin0_runtime_abi::BlockReceiptStatement::try_from_slice(bytes)
        .map_err(|err| Sp1HostError::DecodeOutput(err.to_string()))?
        .output;

    if &actual != expected {
        return Err(Sp1HostError::PublicOutputMismatch {
            expected: Box::new(expected.clone()),
            actual: Box::new(actual),
        });
    }
    Ok(())
}

/// Prove a state transition using the env-driven prover
/// (`SP1_PROVER=cpu|mock|network`).
///
/// # Errors
/// See [`prove_with`].
pub fn prove(
    input: &RuntimeBlockInput,
    witness: StateWitness,
    evidence_proofs: &[EvidenceArtifact],
    prover_address: neutrin0_primitives::Hash,
) -> Result<BlockProof, Sp1HostError> {
    prove_with(
        &ProverClient::from_env(),
        input,
        witness,
        evidence_proofs,
        prover_address,
    )
}

/// Verify a proof using the env-driven prover.
///
/// # Errors
/// See [`verify_with`].
pub fn verify(
    proof: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
    expected: &RuntimeBlockOutput,
) -> Result<(), Sp1HostError> {
    verify_with(&ProverClient::from_env(), proof, vk, expected)
}

/// Bn254-encoded fingerprint of a verifying key.
#[must_use]
pub fn vk_fingerprint(vk: &SP1VerifyingKey) -> String {
    vk.bytes32()
}
