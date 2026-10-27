//! Candidate validation: everything the Guest checks before finality.

use alloc::vec::Vec;
use neutrin0_consensus_types::Chunk;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_primitives::{ChainSpec, ConsensusDomain, Hash, Validator};

use super::{ConsensusError, ConsensusWitness, ValidatedCandidate, genesis_context_with_hash};
use crate::{
    execution::validate_execution_with_hashes,
    history::HistoryError,
    proposer::{Proposers, verify_proposer_with},
    rotation::{ConsensusRecords, read_consensus_records},
};

/// Verify one economic precommit against independently authenticated history.
/// No committee, accepted proof list or aggregate validity is taken from the claim.
///
/// # Errors
/// Rejects wrong source/target/phase/grace, inactive members and invalid signatures.
pub fn verify_participation_vote_using(
    domain: ConsensusDomain,
    incoming_chunk: u64,
    source_chunk: &Chunk,
    source_validators: &[Validator],
    vote: &neutrin0_consensus_types::participation::ParticipationVote,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<neutrin0_consensus_types::participation::ParticipationAcknowledgement, HistoryError> {
    if source_chunk.chunk_id != vote.data.chunk_id {
        return Err(HistoryError::Evidence);
    }
    let acknowledgement =
        neutrin0_consensus_types::participation::acknowledgement_from_participation_vote(
            incoming_chunk,
            source_chunk.hash(),
            source_validators,
            vote,
        )
        .ok_or(HistoryError::Evidence)?;
    let validator = source_validators
        .get(usize::try_from(vote.validator_index).map_err(|_| HistoryError::Evidence)?)
        .ok_or(HistoryError::Evidence)?;
    if !verifier.verify(
        &validator.pubkey,
        &vote.data.signing_message(domain),
        &vote.vote_signature,
    ) {
        return Err(HistoryError::Evidence);
    }
    Ok(acknowledgement)
}

/// Candidate validation plus the values finality composition reuses.
pub(super) struct CandidateParts {
    pub(super) candidate: ValidatedCandidate,
    /// Signing domain of the validated chain specification, hashed once.
    pub(super) domain: ConsensusDomain,
    /// Authenticated chunk-end runtime records, read through one witness state.
    pub(super) records: ConsensusRecords,
}

pub(super) fn validate_candidate_using(
    input: &ConsensusWitness,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<CandidateParts, ConsensusError> {
    let spec = &input.chain_spec;
    let domain = spec.consensus_domain_with(validate_context(input)?);
    let context = &input.context;
    let (mut execution, hashes) = validate_execution_with_hashes(context, &input.blocks)
        .map_err(|_| ConsensusError::Execution)?;
    input
        .history
        .authenticate(context.chunk_id, context.history_root)
        .map_err(ConsensusError::History)?;
    if input.bodies.is_empty() {
        return Err(ConsensusError::Context);
    }
    check_vote_lane_bytes(input)?;
    let (carrier, participation, proving) = select_carried_reports(input, domain, verifier)?;
    let proposers = Proposers::new(
        &context.active_validators,
        &input.seed,
        spec.consensus.expected_proposers_per_slot,
    );
    for ((block, body), hash) in input.blocks.iter().zip(&input.bodies).zip(&hashes) {
        body.validate(&block.header, &block.output.transaction_summary)?;
        check_header_schedule(spec, &block.header)?;
        verify_proposer_with(&block.header, hash, domain, proposers, verifier)
            .map_err(|_| ConsensusError::Proposer)?;
    }
    let offenders =
        check_block_outputs(input, domain, carrier, (participation, proving), verifier)?;
    let (records, next_validators, next_identity_sanctions_root) =
        derive_committee_transition(input, execution.chunk.end_state_root, &offenders)?;
    execution.chunk.next_validator_set_root = commitment(&next_validators);
    execution.chunk.next_identity_sanctions_root = next_identity_sanctions_root;
    Ok(CandidateParts {
        candidate: ValidatedCandidate {
            execution,
            next_validators,
            participation,
            proving,
        },
        domain,
        records,
    })
}

/// The whole chunk's vote lanes stay within the participation byte budget.
fn check_vote_lane_bytes(input: &ConsensusWitness) -> Result<(), ConsensusError> {
    let mut vote_bytes = 0_usize;
    for body in &input.bodies {
        vote_bytes = vote_bytes
            .checked_add(
                neutrin0_consensus_types::participation::vote_lane_bytes(&body.participation_acks)
                    .map_err(|_| ConsensusError::Context)?,
            )
            .ok_or(ConsensusError::Context)?;
    }
    if vote_bytes > neutrin0_consensus_types::participation::MAX_PARTICIPATION_VOTE_BYTES {
        return Err(ConsensusError::Context);
    }
    Ok(())
}

/// The carrier's body index and the participation and proving commitments
/// this chunk consumes from it.
fn select_carried_reports(
    input: &ConsensusWitness,
    domain: ConsensusDomain,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(usize, Hash, Hash), ConsensusError> {
    let spec = &input.chain_spec;
    let context = &input.context;
    // Design 08 carrier rule: in every chunk after chunk 0 exactly one body
    // carries the previous chunk's certificate, a hard fork's first chunk its
    // predecessor's last (design 20); blocks before it consume the start
    // boundary's reports, the carrier and later blocks the derived ones.
    let carriers: Vec<usize> = input
        .bodies
        .iter()
        .enumerate()
        .filter(|(_, body)| body.participation.is_some())
        .map(|(index, _)| index)
        .collect();
    match (spec.carried_chunk(context.chunk_id), carriers.as_slice()) {
        (None, []) => Ok((input.bodies.len(), context.participation, context.proving)),
        (Some(previous), [index]) => {
            let carried = input.bodies[*index]
                .participation
                .as_ref()
                .ok_or(ConsensusError::Context)?;
            let record = input
                .history
                .record(previous)
                .map_err(ConsensusError::History)?;
            let (participation, proving) =
                crate::history::verify_carried_using(domain, spec, record, carried, verifier)
                    .map_err(ConsensusError::History)?;
            Ok((*index, participation.commitment(), proving.commitment()))
        }
        _ => Err(ConsensusError::Context),
    }
}

/// Bind every block output to the anchor, the reports it consumed, its
/// acknowledged participation and its program pieces; collect the identities
/// its safety sanctions admitted.
fn check_block_outputs(
    input: &ConsensusWitness,
    domain: ConsensusDomain,
    carrier: usize,
    reports: (Hash, Hash),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<Vec<Validator>, ConsensusError> {
    let spec = &input.chain_spec;
    let context = &input.context;
    let (participation, proving) = reports;
    let mut offenders = Vec::new();
    let expected_anchor = neutrin0_consensus_types::evidence::EvidenceAnchor {
        fact_guest_vk_digest: context.programs.execution.fact,
        chain_spec_hash: domain.chain_spec_hash,
        chunk_id: context.chunk_id,
        history_root: context.history_root,
        block_guest_vk_digest: context.programs.execution.block,
        evidence_guest_vk_digest: context.programs.execution.evidence,
        unbonding_delay_blocks: spec.runtime.unbonding_delay_blocks,
        chunk_size: context.chunk_size,
        max_block_proving_input_bytes: spec.proof.max_block_proving_input_bytes,
        block_gas_limit: spec.genesis_gas_limit,
    };
    // Each source seat is acknowledged at most once per chunk, so repeated
    // precommits cannot buy signature verification here.
    let mut seats = alloc::collections::BTreeSet::new();
    for (index, (block, body)) in input.blocks.iter().zip(&input.bodies).enumerate() {
        // Blocks from the carrier on consume this candidate's selection, not a
        // locally collected certificate subset; earlier ones the start
        // boundary's reports.
        let (expected_participation, expected_proving) = if index < carrier {
            (context.participation, context.proving)
        } else {
            (participation, proving)
        };
        if block.output.accountability.anchor != expected_anchor
            || block.output.participation != expected_participation
            || block.output.proving != expected_proving
        {
            return Err(ConsensusError::Context);
        }
        let mut acknowledgements = alloc::collections::BTreeSet::new();
        for vote in &body.participation_acks {
            if !seats.insert(vote.source_seat()) {
                return Err(ConsensusError::Context);
            }
            let source = input
                .history
                .record(vote.data.chunk_id)
                .map_err(ConsensusError::History)?;
            acknowledgements.insert(
                verify_participation_vote_using(
                    domain,
                    context.chunk_id,
                    &source.chunk,
                    &source.validators,
                    vote,
                    verifier,
                )
                .map_err(ConsensusError::History)?,
            );
        }
        if acknowledgements.len() > neutrin0_consensus_types::participation::MAX_PARTICIPATION_ACKS
            || block.output.participation_acks
                != neutrin0_consensus_types::participation::acknowledgement_commitment(
                    &acknowledgements.into_iter().collect::<Vec<_>>(),
                )
        {
            return Err(ConsensusError::Context);
        }
        // The runtime records published program pieces from these
        // references; each must authenticate its piece in its artifact
        // (design 20).
        if block.output.program_pieces
            != neutrin0_consensus_types::program_pieces_commitment(&body.program_refs()?)
        {
            return Err(ConsensusError::Context);
        }
        for sanction in &block.output.accountability.admitted {
            if sanction.kind == neutrin0_consensus_types::evidence::SanctionKind::Slash {
                offenders.push(sanction.offender.clone());
            }
        }
    }
    Ok(offenders)
}

/// Read the chunk-end runtime records, apply the identity sanctions and
/// derive the next committee with the sanctions trie root it leaves.
fn derive_committee_transition(
    input: &ConsensusWitness,
    end_state_root: Hash,
    offenders: &[Validator],
) -> Result<(ConsensusRecords, Vec<Validator>, Hash), ConsensusError> {
    let spec = &input.chain_spec;
    let context = &input.context;
    let records = read_consensus_records(end_state_root, &input.post_state)
        .map_err(|_| ConsensusError::Rotation)?;
    let required = crate::identity_sanctions::witness_keys(
        &context.active_validators,
        records.candidates(),
        offenders,
    );
    let mut sanctions = crate::identity_sanctions::authenticate_witness(
        context.identity_sanctions_root,
        &input.identity_sanctions,
        &required,
    )
    .map_err(|_| ConsensusError::Rotation)?;
    let (previous_validators, candidates) = crate::identity_sanctions::apply(
        &mut sanctions,
        &context.active_validators,
        records.candidates(),
        offenders,
    )
    .map_err(|_| ConsensusError::Rotation)?;
    let next_validators = crate::rotation::derive_next_validators(
        &previous_validators,
        &candidates,
        &spec.consensus,
        spec.runtime.unbonding_delay_blocks,
        context.chunk_id,
    )
    .map_err(|_| ConsensusError::Rotation)?;
    let next_identity_sanctions_root =
        neutrin0_runtime_core::StateBackend::post_state_root(&sanctions);
    Ok((records, next_validators, next_identity_sanctions_root))
}

/// A header's timestamp must be exactly its slot's scheduled start, so chain
/// time is the slot schedule and no proposer can move it; and its gas limit
/// the chain's: the runtime executes under the header's limit, so only this
/// check stops a proposer from lifting the block gas bound.
fn check_header_schedule(
    spec: &ChainSpec,
    header: &neutrin0_consensus_types::Header,
) -> Result<(), ConsensusError> {
    let timestamp = header
        .slot
        .checked_mul(spec.consensus.slot_duration_secs)
        .and_then(|seconds| seconds.checked_add(spec.genesis_time))
        .ok_or(ConsensusError::Header)?;
    if header.timestamp != timestamp || header.gas_limit != spec.genesis_gas_limit {
        return Err(ConsensusError::Header);
    }
    Ok(())
}

/// Check the witness against its chain specification and return the
/// specification hash, computed once for every later binding.
fn validate_context(input: &ConsensusWitness) -> Result<Hash, ConsensusError> {
    let context = &input.context;
    let spec = &input.chain_spec;
    spec.validate().map_err(|_| ConsensusError::Context)?;
    let spec_hash = spec.hash();
    // The witness programs must be the ones the incoming boundary names; the
    // chunk receipt is only meaningful under that exact set.
    if context.chain_spec_hash != spec_hash
        || context.chain_id != spec.chain_id
        || context.chunk_size != spec.consensus.chunk_size
        || !spec.accepts_programs(&context.programs)
        || context.vm_code_hash != context.programs.runtime_code_hash
        || input.blocks.len() != input.bodies.len()
    {
        return Err(ConsensusError::Context);
    }
    // The first chunk starts at the boundary the specification pins: genesis,
    // or a hard fork's start (design 20). Lower chunks belong to a predecessor.
    let first = spec.first_chunk();
    if context.chunk_id < first
        || (context.chunk_id == first
            && (context.programs != spec.genesis_programs()
                || match &spec.fork {
                    None => {
                        context != &genesis_context_with_hash(spec, spec_hash, context.programs)
                            || input.seed != spec.genesis_seed
                    }
                    Some(fork) => super::context_boundary(context, input.seed)? != fork.start,
                }))
    {
        return Err(ConsensusError::Context);
    }
    // A scheduled hard fork ends this chain: its successor proves the fork's
    // count and every later chunk (design 20).
    if context
        .fork
        .is_some_and(|fork| context.chunk_id >= fork.count)
    {
        return Err(ConsensusError::Context);
    }
    let mut requested: alloc::collections::BTreeSet<_> = input
        .bodies
        .iter()
        .flat_map(|body| {
            body.participation_acks
                .iter()
                .map(|vote| vote.data.chunk_id)
        })
        .collect();
    if let Some(carried) = spec.carried_chunk(context.chunk_id) {
        requested.insert(carried);
    }
    if requested.len() != input.history.records.len()
        || requested
            .iter()
            .zip(&input.history.records)
            .any(|(id, opening)| *id != opening.record.chunk.chunk_id)
    {
        return Err(ConsensusError::Context);
    }
    Ok(spec_hash)
}
