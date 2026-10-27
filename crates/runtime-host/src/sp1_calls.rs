//! SP1 SDK calls shared by every proof kind: compressed proving, queuing
//! child receipts for recursion and containing upstream verifier panics.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use neutrin0_proof_system::ProofError;
use sp1_sdk::{
    SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey, blocking::ProveRequest,
};

use crate::{ProgramProver, backend};

/// Prove `stdin` as a Compressed STARK with deferred (recursive) proof
/// verification enabled, as every block, evidence and chunk proof is.
pub(super) fn prove_compressed<P: ProgramProver>(
    prover: &P,
    pk: &P::ProvingKey,
    stdin: SP1Stdin,
) -> Result<SP1ProofWithPublicValues, P::Error> {
    prover.submit(backend::submission_priority(), || {
        prover
            .prove(pk, stdin)
            .deferred_proof_verification(true)
            .compressed()
            .run()
    })
}

/// Queue a compressed child receipt on `stdin` for recursive verification
/// under `vk`.
pub(super) fn push_receipt(
    stdin: &mut SP1Stdin,
    bundle: &SP1ProofWithPublicValues,
    vk: &SP1VerifyingKey,
) -> Result<(), ProofError> {
    let SP1Proof::Compressed(inner) = &bundle.proof else {
        return Err(ProofError::MalformedProof);
    };
    stdin.write_proof(*inner.clone(), vk.vk.clone());
    Ok(())
}

/// Contain an upstream verifier panic on malformed adversarial input.
/// Host builds require unwinding; a panic never establishes a slashable verdict.
pub(super) fn guarded<T>(verify: impl FnOnce() -> T) -> Result<T, ProofError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(verify))
        .map_err(|_| ProofError::BackendRejected)
}
