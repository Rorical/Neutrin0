//! Objective signed-commitment checks shared with the chunk guest.
//!
//! Proof rejection must additionally be established by the configured proof
//! verifier. A local rejection cache is not a substitute for these bindings.

use neutrin0_consensus_types::{
    BlockProof, FinalityVoteData, FinalityVotePhase, IndexedVote, VoteAttestation,
};
use neutrin0_primitives::{Hash, Validator};

use crate::finality::is_active;
use neutrin0_consensus_types::evidence::commitment;

mod da;
mod lock;
#[cfg(test)]
mod tests;

pub use da::{da_publication_message, verify_da_fraud, verify_da_fraud_using};
pub(crate) use lock::{VerifiedQuorums, verify_quorum_with, verify_unlock_with};
pub use lock::{
    verify_lock_violation, verify_lock_violation_using, verify_quorum, verify_quorum_using,
    verify_unlock_quorum, verify_unlock_using,
};

/// Authenticate exact same-round, same-phase nil/value equivocation.
pub fn verify_conflicting_nil_vote_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    value: &IndexedVote,
    nil: &neutrin0_consensus_types::IndexedNilVote,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if value.data.chunk_id != nil.data.chunk_id
        || value.data.round != nil.data.round
        || value.data.phase != nil.data.phase
    {
        return Err(EvidenceError::Binding);
    }
    let validator = validators
        .get(index as usize)
        .filter(|validator| is_active(validator))
        .ok_or(EvidenceError::Binding)?;
    verify_indexed_vote_using(domain, validators, index, value, verifier)?;
    if !verifier.verify(
        &validator.pubkey,
        &nil.data.signing_message(domain),
        &nil.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Authenticate designated-leader equivocation without assuming either carried
/// unlock QC is valid. The signed conflicting target alone establishes guilt.
pub fn verify_double_bft_proposal_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    seed: &neutrin0_primitives::Seed,
    index: u32,
    first: &neutrin0_consensus_types::BftProposal,
    second: &neutrin0_consensus_types::BftProposal,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    verify_double_bft_proposal_with_root(
        domain,
        validators,
        commitment(validators),
        seed,
        index,
        first,
        second,
        verifier,
    )
}

/// [`verify_double_bft_proposal_using`] for a caller already holding
/// `root == commitment(validators)`.
#[allow(
    clippy::too_many_arguments,
    reason = "The proposals' exact chunk context: domain, set, its root and seed."
)]
pub(crate) fn verify_double_bft_proposal_with_root(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    root: Hash,
    seed: &neutrin0_primitives::Seed,
    index: u32,
    first: &neutrin0_consensus_types::BftProposal,
    second: &neutrin0_consensus_types::BftProposal,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if first.chunk.chunk_id != second.chunk.chunk_id
        || first.round != second.round
        || first.proposer_index != index
        || second.proposer_index != index
        // The BFT value is the chunk with its payment selection (design 08):
        // two proposals differing in either split the round's voters.
        || (first.chunk.hash() == second.chunk.hash() && first.selection() == second.selection())
        || neutrin0_consensus_types::bft::bft_leader_with_root(
            domain.chain_id,
            first.chunk.chunk_id,
            first.round,
            seed,
            validators,
            root,
        ) != Some(index)
        || first.chunk.active_validator_set_root != root
        || second.chunk.active_validator_set_root != root
    {
        return Err(EvidenceError::Binding);
    }
    let validator = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !verifier.verify(
        &validator.pubkey,
        &first.signing_message(domain),
        &first.signature,
    ) || !verifier.verify(
        &validator.pubkey,
        &second.signing_message(domain),
        &second.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Evidence failed authentication or does not establish a violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    /// Target, index, phase or canonical proof position differs.
    Binding,
    /// A required validator signature is invalid.
    Signature,
    /// The locking quorum is invalid.
    Quorum,
    /// The carried, signed unlock certificate permits the switch.
    HonestUnlock,
}

/// Verify the exact signed acceptance/unlock statement.
pub fn verify_attestation(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &FinalityVoteData,
    attestation: &VoteAttestation,
) -> Result<(), EvidenceError> {
    verify_attestation_using(
        domain,
        validators,
        index,
        vote,
        attestation,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_attestation_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &FinalityVoteData,
    attestation: &VoteAttestation,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    verify_attestation_with(
        domain,
        validators,
        index,
        vote,
        &vote.signing_message(domain),
        attestation,
        verifier,
    )
}

/// [`verify_attestation_using`] with `vote_message == vote.signing_message(domain)`
/// already encoded, so every attestation of one envelope shares it.
pub(crate) fn verify_attestation_with(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &FinalityVoteData,
    vote_message: &[u8],
    attestation: &VoteAttestation,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    if attestation.validator_index != index || attestation.vote != *vote {
        return Err(EvidenceError::Binding);
    }
    // The bound vote equals `vote`, so its individual signature covers `vote_message`.
    let key = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !verifier.verify(&key.pubkey, vote_message, &attestation.vote_signature) {
        return Err(EvidenceError::Signature);
    }
    if !verifier.verify(
        &key.pubkey,
        &attestation.signing_message(domain),
        &attestation.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Bind complete proof bytes and metadata to their signed chunk position.
pub fn verify_proof_acceptance(
    attestation: &VoteAttestation,
    proof: &BlockProof,
    opening: &neutrin0_consensus_types::ProofAcceptanceOpening,
    chunk_size: u64,
) -> Result<(), EvidenceError> {
    let offset = attestation
        .vote
        .chunk_id
        .checked_mul(chunk_size)
        .and_then(|start| proof.height.checked_sub(start))
        .and_then(|position| position.checked_sub(1))
        .ok_or(EvidenceError::Binding)?;
    if attestation.vote.phase != FinalityVotePhase::Precommit
        || chunk_size == 0
        || opening.index != offset
        || attestation.proof_acceptance.is_none_or(|acceptance| {
            acceptance.count != chunk_size || !acceptance.verify(&commitment(proof), opening)
        })
    {
        return Err(EvidenceError::Binding);
    }
    Ok(())
}

/// Verify an individual finality vote under its chain and phase domains, with
/// a shared key cache or an authenticated fact source.
pub fn verify_indexed_vote_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    vote: &IndexedVote,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    let key = validators
        .get(index as usize)
        .ok_or(EvidenceError::Binding)?;
    if !verifier.verify(
        &key.pubkey,
        &vote.data.signing_message(domain),
        &vote.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}
