//! Cached prover handle plus the block Guest's keys for repeated proving.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use std::sync::OnceLock;

use neutrin0_consensus_types::evidence::EvidenceArtifact;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_abi::RuntimeBlockOutput;
use neutrin0_runtime_abi::StateWitness;
use sp1_sdk::{
    Elf, ExecutionReport, ProvingKey, SP1ProofWithPublicValues, SP1PublicValues, SP1VerifyingKey,
    blocking::{Prover, ProverClient},
};

use crate::{
    BlockProof, EVIDENCE_GUEST_ELF, EVM_GUEST_ELF, ProgramProver, Sp1HostError, block_stdin,
    prove_compressed, sdk_err, verify_with,
};

/// Cached prover + proving/verifying keys for a single guest ELF.
///
/// `prover.setup(elf)` is the expensive preprocessing pass; keeping it
/// behind a [`ProverCtx`] avoids paying it for every proof. The keys
/// are deterministic for a given `(sp1_version, elf_bytes)` tuple, so
/// callers may also persist `vk`; chain specifications pin the program identity.
pub struct ProverCtx<P: Prover> {
    /// Underlying prover (env, cpu, mock, network, light, cuda).
    pub prover: P,
    /// Preprocessed proving key for this context's program.
    pub pk: P::ProvingKey,
    /// Verifying key bound to this context's program.
    pub vk: SP1VerifyingKey,
    /// Verifying key of [`EVIDENCE_GUEST_ELF`], set up on the first
    /// block that carries evidence attachments.
    evidence_vk: OnceLock<SP1VerifyingKey>,
}

impl<P: ProgramProver> ProverCtx<P> {
    /// Build a context by running `prover.setup(EVM_GUEST_ELF)` once.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` fails.
    pub fn new(prover: P) -> Result<Self, Sp1HostError> {
        Self::new_cached_for(prover, EVM_GUEST_ELF.clone())
    }

    fn with_key(prover: P, pk: P::ProvingKey) -> Self {
        let vk = pk.verifying_key().clone();
        Self {
            prover,
            pk,
            vk,
            evidence_vk: OnceLock::new(),
        }
    }

    /// Evidence verifying key for a block with `evidence_proofs`, set up
    /// once per context and only when the block carries attachments.
    fn evidence_key(
        &self,
        evidence_proofs: &[EvidenceArtifact],
    ) -> Result<Option<&SP1VerifyingKey>, Sp1HostError> {
        if evidence_proofs.is_empty() {
            return Ok(None);
        }
        if let Some(key) = self.evidence_vk.get() {
            return Ok(Some(key));
        }
        let key = embedded_evidence_vk(&self.prover)?;
        Ok(Some(self.evidence_vk.get_or_init(|| key)))
    }

    /// Produce a proof using the cached keys.
    ///
    /// # Errors
    /// See [`prove_with`](crate::prove_with).
    pub fn prove(
        &self,
        input: &RuntimeBlockInput,
        witness: StateWitness,
        evidence_proofs: &[EvidenceArtifact],
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<BlockProof, Sp1HostError> {
        let evidence_vk = self.evidence_key(evidence_proofs)?;
        let stdin = block_stdin(
            input,
            &witness,
            evidence_proofs,
            evidence_vk,
            prover_address,
        )?;
        let proof = prove_compressed(&self.prover, &self.pk, stdin).map_err(sdk_err)?;

        Ok(BlockProof {
            proof,
            vk: self.vk.clone(),
            witness,
        })
    }

    /// Verify a proof against this context's verifying key.
    ///
    /// # Errors
    /// See [`verify_with`].
    pub fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        expected: &RuntimeBlockOutput,
    ) -> Result<(), Sp1HostError> {
        verify_with(&self.prover, proof, &self.vk, expected)
    }

    /// Run the guest under the executor (no proof generated) and return
    /// the committed public values plus the execution report.
    ///
    /// Useful for fast negative tests: a guest panic surfaces as
    /// `report.exit_code != 0`, which the real cryptographic verifier
    /// would also reject via `StatusCode::SUCCESS`. The mock prover's
    /// `verify` ignores status codes for compressed proofs, so the
    /// execution report is the only mock-friendly way to assert the
    /// guest actually aborted.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if the executor itself failed
    /// before reaching the guest, or [`Sp1HostError::Codec`] if the
    /// input could not be borsh-encoded.
    pub fn execute(
        &self,
        input: &RuntimeBlockInput,
        witness: &StateWitness,
        evidence_proofs: &[EvidenceArtifact],
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<(SP1PublicValues, ExecutionReport), Sp1HostError> {
        let evidence_vk = self.evidence_key(evidence_proofs)?;
        let stdin = block_stdin(input, witness, evidence_proofs, evidence_vk, prover_address)?;
        self.prover
            .execute(self.pk.elf().clone(), stdin)
            .deferred_proof_verification(true)
            .run()
            .map_err(sdk_err)
    }
}

impl<P> ProverCtx<P>
where
    P: ProgramProver,
{
    /// Build a context for `elf` through the prover's program setup.
    ///
    /// CPU keys reuse disk-cached ROM preprocessing, keyed by ELF hash and
    /// SP1 circuit identity. CUDA retains a live server session key whose
    /// verifying key must match the locally cached program identity.
    ///
    /// # Errors
    /// Returns [`Sp1HostError::Sdk`] if `setup` is reached and fails.
    /// Disk errors are non-fatal — they fall back to `setup`.
    pub fn new_cached_for(prover: P, elf: Elf) -> Result<Self, Sp1HostError> {
        let pk = prover.setup_program(elf)?;
        Ok(Self::with_key(prover, pk))
    }
}

/// Process-wide cache for the env-driven prover context. Subsequent
/// calls to [`default_ctx`] return the same handle without re-running
/// `setup`.
static DEFAULT_CTX: OnceLock<ProverCtx<sp1_sdk::blocking::EnvProver>> = OnceLock::new();

/// Lazily-initialised default prover context (uses `SP1_PROVER` env var).
///
/// # Errors
/// Propagates setup failures the first time it is called. Subsequent
/// calls return the cached context regardless.
pub fn default_ctx() -> Result<&'static ProverCtx<sp1_sdk::blocking::EnvProver>, Sp1HostError> {
    if let Some(ctx) = DEFAULT_CTX.get() {
        return Ok(ctx);
    }
    let ctx = ProverCtx::new(ProverClient::from_env())?;
    Ok(DEFAULT_CTX.get_or_init(|| ctx))
}

/// Verifying key of [`EVIDENCE_GUEST_ELF`] under `prover`.
pub(super) fn embedded_evidence_vk<P: ProgramProver>(
    prover: &P,
) -> Result<SP1VerifyingKey, Sp1HostError> {
    Ok(prover
        .setup_program(EVIDENCE_GUEST_ELF.clone())?
        .verifying_key()
        .clone())
}
