//! Authenticated History tokens keep expensive verification outside engine locks.

use neutrin0_consensus_types::history_proof::{HistoryProof, ProofDomain};
use neutrin0_primitives::ChainSpec;

use crate::{ProofError, ProofSystem};

/// A cryptographically authenticated History proof.
///
/// Its end follows from the specification's start (genesis or a hard fork's
/// start) under the chain's rules. It is not a canonicality or latestness
/// claim, and an anchor after that start still needs its opening.
/// Construction always invokes the selected backend's real History verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHistory {
    proof: HistoryProof,
    domain: ProofDomain,
}

impl VerifiedHistory {
    /// Exact authenticated artifact, suitable for atomic persistence.
    pub const fn proof(&self) -> &HistoryProof {
        &self.proof
    }

    /// Independently derived trusted program and chain profile.
    pub const fn domain(&self) -> &ProofDomain {
        &self.domain
    }

    /// Consume the verification token after all canonical-boundary checks.
    pub fn into_proof(self) -> HistoryProof {
        self.proof
    }
}

/// Authenticate exact bytes once before handing a History proof to an engine
/// or a light client.
///
/// The receipt is verified under the chunk Guest of the chain binding the
/// backend derives from `spec` and its own embedded programs, never one the
/// receipt names. Callers still check the end against their own trust anchor
/// or canonical state before committing.
pub fn verify_history_proof<P: ProofSystem + ?Sized>(
    backend: &P,
    spec: &ChainSpec,
    proof: HistoryProof,
) -> Result<VerifiedHistory, ProofError> {
    let domain = backend.history_domain(spec)?;
    let statement = &proof.statement.statement;
    if !domain.is_valid(spec)
        || statement.chain != domain.chain
        || !statement.end.is_well_formed(spec)
        || statement.end.next_chunk_id == 0
    {
        return Err(ProofError::PublicInputMismatch);
    }
    backend.verify_history(&proof, &domain.chunk)?;
    Ok(VerifiedHistory { proof, domain })
}
