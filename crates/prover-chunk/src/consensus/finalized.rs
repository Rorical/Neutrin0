//! Finality composition: the certificate, its receipt choices and the
//! ratified proof over a validated candidate.

use neutrin0_consensus_types::Chunk;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history_proof::{ChainBinding, ConsensusStatement};

use super::candidate::{CandidateParts, validate_candidate_using};
use super::successor::{Successor, derive_successor};
use super::{
    ConsensusError, ConsensusWitness, MAX_CONSENSUS_FACT_STATEMENTS, ValidatedCandidate,
    ValidatedConsensus, as_chunk, context_boundary,
};
use crate::{finality::verify_finality_with_root, history::HistoryError};

/// Build the fact-first verifier for `input`; malformed statements fail closed.
pub(super) fn hybrid_verifier(
    input: &ConsensusWitness,
) -> Result<crate::facts::HybridVerifier, ConsensusError> {
    if input.facts.len() > MAX_CONSENSUS_FACT_STATEMENTS {
        return Err(ConsensusError::History(HistoryError::Evidence));
    }
    crate::facts::HybridVerifier::new(&input.facts).map_err(ConsensusError::History)
}

/// Verify consensus once and retain the ordinary-execution context for the host.
///
/// Signature checks covered by `input.facts` are answered from those
/// statements; the rest are batched in-circuit. The result is identical
/// either way, so the host may prepare a witness with any subset of facts.
pub fn validate_consensus_with_context(
    input: &ConsensusWitness,
) -> Result<ValidatedConsensus, ConsensusError> {
    let mut verifier = hybrid_verifier(input)?;
    let validated = validate_consensus_using(input, &mut verifier)?;
    if !verifier.finish() {
        return Err(ConsensusError::Finality);
    }
    Ok(validated)
}

/// Fact-coverage report for a witness: how many checks facts answered and
/// how many still ran in-circuit. Useful for sizing the early fact worker.
pub fn fact_coverage(input: &ConsensusWitness) -> Result<(usize, usize), ConsensusError> {
    let mut verifier = hybrid_verifier(input)?;
    validate_consensus_using(input, &mut verifier)?;
    let (hits, misses) = (verifier.hits(), verifier.misses());
    if !verifier.finish() {
        return Err(ConsensusError::Finality);
    }
    Ok((hits, misses))
}

/// Run every consensus check through `verifier` without settling it.
///
/// Callers must settle the verifier afterwards (for batched verifiers) or
/// otherwise confirm every answer it gave. The host uses this with a
/// recording verifier to learn which fact requests a chunk needs.
pub fn validate_consensus_using(
    input: &ConsensusWitness,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<ValidatedConsensus, ConsensusError> {
    let CandidateParts {
        candidate,
        domain,
        mut records,
    } = validate_candidate_using(input, verifier)?;
    let ValidatedCandidate {
        execution,
        next_validators,
        participation,
        proving,
    } = candidate;
    let context = &input.context;
    let spec = &input.chain_spec;
    let chunk = as_chunk(&execution.chunk);
    // Execution derived this root as `commitment(&context.active_validators)`.
    verify_finality_with_root(
        domain,
        &spec.consensus,
        &context.active_validators,
        execution.chunk.active_validator_set_root,
        &input.seed,
        &chunk,
        &input.finality_cert,
        verifier,
    )
    .map_err(|_| ConsensusError::Finality)?;
    check_receipt_choices(input, &chunk)?;
    // The successor follows from the candidate alone: alternative
    // certificates for this same candidate cannot change its outgoing
    // boundary or the reports its carrier selected (design 08).
    let Successor {
        start,
        end,
        next_context,
        ..
    } = derive_successor(
        input,
        &execution,
        next_validators,
        (participation, proving),
        &mut records,
    )?;
    Ok(ValidatedConsensus {
        statement: ConsensusStatement {
            chain: ChainBinding::with_hash(domain.chain_spec_hash),
            start,
            end,
            chunk: execution.chunk,
            finality_cert_hash: commitment(&input.finality_cert),
        },
        next_context,
    })
}

/// Design 08: the certificate names exactly one receipt per height. The
/// proposal's statement keys must be the verified receipts' statements, and
/// a receipt that is not the proposer's is selectable only once the
/// exclusive window after the block's slot has passed (rule W). Rules P and
/// L compare against receipts the certificate does not carry and are
/// enforced by the voters.
fn check_receipt_choices(input: &ConsensusWitness, chunk: &Chunk) -> Result<(), ConsensusError> {
    let spec = &input.chain_spec;
    let proposal = &input.finality_cert.proposal;
    if proposal.receipts.len() != input.blocks.len()
        || input
            .blocks
            .last()
            .is_some_and(|block| proposal.proposal_slot < block.header.slot)
    {
        return Err(ConsensusError::Finality);
    }
    if !neutrin0_consensus_types::proving::ratifies_previous(
        &proposal.ratified_chunk_proofs,
        spec.previous_chunk(chunk.chunk_id),
    ) {
        return Err(ConsensusError::Finality);
    }
    check_ratified_proof(input)?;
    for (block, choice) in input.blocks.iter().zip(&proposal.receipts) {
        // The runtime pays only runtime accounts: a choice crediting any
        // other value could never be settled.
        if commitment(&block.statement()) != choice.statement_key
            || block.prover_address != choice.prover_address
            || !neutrin0_primitives::is_runtime_account(&choice.prover_address)
        {
            return Err(ConsensusError::Finality);
        }
        if block.prover_address != block.public_inputs.proposer_address
            && proposal.proposal_slot
                < block
                    .header
                    .slot
                    .saturating_add(spec.consensus.proof_exclusive_slots)
        {
            return Err(ConsensusError::Finality);
        }
    }
    Ok(())
}

/// Design 08: every certificate after a chain's first chunk ratifies exactly
/// the previous chunk's proof, and the Guest verifies that proof. The witness
/// carries its public values, which the guest program verifies recursively
/// under the specification's chunk Guest; here they must be the entry's
/// statement and prover, name this chain and end exactly at this chunk's start
/// boundary. That proof is not conditional on its own start: it verified its
/// predecessor's proof the same way, back to the specification's first
/// boundary, so ending here proves this start from that boundary (design 13).
fn check_ratified_proof(input: &ConsensusWitness) -> Result<(), ConsensusError> {
    let list = &input.finality_cert.proposal.ratified_chunk_proofs;
    if list.len() != input.ratified.len() {
        return Err(ConsensusError::Finality);
    }
    let (Some(entry), Some(ratified)) = (list.first(), input.ratified.first()) else {
        return Ok(());
    };
    let incoming = context_boundary(&input.context, input.seed)?;
    let chain = ChainBinding::new(&input.chain_spec);
    if ratified.statement_key() != entry.statement_key
        || ratified.chunk_prover_address != entry.prover_address
        || !neutrin0_primitives::is_runtime_account(&entry.prover_address)
        || ratified.statement.finality_cert_hash != entry.finality_cert_hash
        || ratified.statement.chain != chain
        || ratified.statement.chunk.chunk_id != entry.chunk_id
        || ratified.statement.end != incoming
    {
        return Err(ConsensusError::Finality);
    }
    Ok(())
}
