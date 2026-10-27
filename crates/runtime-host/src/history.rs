//! Real compressed-STARK verification of History proofs: chunk receipts that
//! recursively prove the whole chain from genesis (design 13).

#![allow(clippy::redundant_pub_crate)]

use std::sync::OnceLock;

use neutrin0_consensus_types::history_proof::{ChainBinding, HistoryProof, ProofDomain, VkDigest};
use neutrin0_primitives::ChainSpec;
use neutrin0_proof_system::ProofError;
use sp1_sdk::{
    SP1Proof,
    blocking::{LightProver, Prover, ProverClient},
};

use crate::{ProgramProver, Sp1ProofSystem, guarded, proof_system::Sp1ChunkProof};

/// One process-wide light verifier. It is independent of the configured
/// prover, so receipts from `MockProver` never verify.
fn light_verifier() -> &'static LightProver {
    static VERIFIER: OnceLock<LightProver> = OnceLock::new();
    VERIFIER.get_or_init(|| ProverClient::builder().light().build())
}

impl<P: ProgramProver> Sp1ProofSystem<P> {
    /// The trust profile `spec` pins, accepted only when this backend derived
    /// the same Fact and chunk Guest keys locally: the chain binding and the
    /// starting program set.
    pub(super) fn trusted_history_domain(
        &self,
        spec: &ChainSpec,
    ) -> Result<ProofDomain, ProofError> {
        spec.validate().map_err(|_| ProofError::InvalidWitness)?;
        if spec.genesis_execution.fact != self.embedded.execution.fact
            || spec.genesis_chunk != self.embedded.chunk
        {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(ProofDomain {
            chain: ChainBinding::new(spec),
            chunk: spec.genesis_chunk,
            programs: spec.genesis_programs(),
        })
    }

    /// Verify a History proof under `chunk`, the chunk Guest of the
    /// specification the caller trusts; the caller compares the statement's
    /// chain binding with that specification's. The installed program verifies
    /// with its full key through the independent light verifier; any other
    /// identity is checked by digest. Neither path accepts mock receipts, and
    /// the key is never taken from the receipt itself.
    pub(super) fn verify_history_receipt(
        &self,
        proof: &HistoryProof,
        chunk: &VkDigest,
    ) -> Result<(), ProofError> {
        guarded(|| {
            let statement = &proof.statement.statement;
            let fact = self.embedded.execution.fact;
            if [statement.start.programs, statement.end.programs]
                .iter()
                .any(|programs| !programs.is_complete() || programs.execution.fact != fact)
            {
                return Err(ProofError::PublicInputMismatch);
            }
            let wire: Sp1ChunkProof = borsh::from_slice(proof.receipt.as_ref())
                .map_err(|_| ProofError::MalformedProof)?;
            let bundle = wire.to_sp1().map_err(|_| ProofError::MalformedProof)?;
            if !matches!(bundle.proof, SP1Proof::Compressed(_)) {
                return Err(ProofError::MalformedProof);
            }
            let expected =
                borsh::to_vec(&proof.statement).map_err(|_| ProofError::MalformedProof)?;
            if bundle.public_values.as_slice() != expected {
                return Err(ProofError::PublicInputMismatch);
            }
            if let Ok(keys) = self.keys(chunk) {
                return guarded(|| light_verifier().verify(&bundle, &keys.vk, None))?
                    .map_err(|_| ProofError::BackendRejected);
            }
            neutrin0_prover_chunk::proof_verification::verify_typed_receipt(
                &bundle.proof,
                bundle.public_values.as_slice(),
                &bundle.sp1_version,
                &proof.statement,
                chunk,
            )
            .map_err(|_| ProofError::BackendRejected)
        })?
    }
}

impl<P: ProgramProver> neutrin0_light_client::HistoryVerifier for Sp1ProofSystem<P> {
    type Error = ProofError;
    fn verify_history(&self, proof: &HistoryProof, chunk: &VkDigest) -> Result<(), ProofError> {
        self.verify_history_receipt(proof, chunk)
    }
}
