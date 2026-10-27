//! Previous-chunk participation quorums and carried certificates (design 08).
#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use neutrin0_consensus_types::QuorumCertificate;
use neutrin0_primitives::{ChainSpec, ConsensusDomain, ConsensusParams};

use super::HistoryError;
use super::records::HistoricalSource;

/// Authenticate a previous-chunk precommit quorum selected in committed data.
/// The caller supplies its validated specification and authenticates `record`
/// against the incoming history root.
///
/// # Errors
/// Rejects the wrong phase/target, malformed membership, insufficient stake or
/// a signature that does not authenticate the exact chain-bound precommit.
pub fn verify_participation(
    spec: &ChainSpec,
    record: &impl HistoricalSource,
    certificate: &QuorumCertificate,
) -> Result<neutrin0_consensus_types::participation::ParticipationReport, HistoryError> {
    let mut verifier = crate::bls::DirectVerifier::default();
    verify_participation_using(
        spec.consensus_domain(),
        &spec.consensus,
        record,
        certificate,
        &mut verifier,
    )
}

/// Participation verification with a shared native or authenticated Fact verifier.
pub(crate) fn verify_participation_using(
    domain: ConsensusDomain,
    params: &ConsensusParams,
    record: &impl HistoricalSource,
    certificate: &QuorumCertificate,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<neutrin0_consensus_types::participation::ParticipationReport, HistoryError> {
    crate::finality::verify_participation_with(
        domain,
        params,
        record.validators(),
        record.chunk(),
        certificate,
        verifier,
    )
    .map_err(|_| HistoryError::Evidence)?;
    neutrin0_consensus_types::participation::ParticipationReport::from_certificate(
        record.chunk().chunk_id,
        record.validators(),
        &certificate.aggregate.aggregation_bits,
    )
    .ok_or(HistoryError::Evidence)
}

/// Verify the previous chunk's carried certificate and derive both reports
/// (design 08): the quorum as [`verify_participation_using`] does, then the
/// compact leader proposal against the record's chunk and committee, its
/// round, its leader and signature, and its ratification list, each under
/// the specification in force at that chunk. A hard fork's first chunk also
/// credits the endpoint prover `spec` pins (design 20).
pub(crate) fn verify_carried_using(
    domain: ConsensusDomain,
    spec: &ChainSpec,
    record: &impl HistoricalSource,
    carried: &neutrin0_consensus_types::proving::CarriedCertificate,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<
    (
        neutrin0_consensus_types::participation::ParticipationReport,
        neutrin0_consensus_types::proving::ProvingReport,
    ),
    HistoryError,
> {
    let participation =
        verify_participation_using(domain, &spec.consensus, record, &carried.quorum, verifier)?;
    let chunk = record.chunk();
    let validators = record.validators();
    let proposal = &carried.proposal;
    // The quorum signed the carried selection with the chunk (design 08), so
    // every certificate of the chunk carries the same one.
    if proposal.round != carried.quorum.data.round
        || carried.quorum.data.selection != proposal.selection()
        || (proposal.round == 0) != proposal.round_change_certificate.is_none()
        || neutrin0_consensus_types::bft_leader(
            domain.chain_id,
            chunk.chunk_id,
            proposal.round,
            record.seed(),
            validators,
        ) != Some(proposal.proposer_index)
        || !neutrin0_consensus_types::proving::ratifies_previous(
            &proposal.ratified_chunk_proofs,
            domain.previous_chunk(chunk.chunk_id),
        )
    {
        return Err(HistoryError::Evidence);
    }
    let leader = validators
        .get(proposal.proposer_index as usize)
        .ok_or(HistoryError::Evidence)?;
    if !verifier.verify(
        &leader.pubkey,
        &proposal.signing_message(domain, chunk),
        &proposal.signature,
    ) {
        return Err(HistoryError::Evidence);
    }
    let mut proving = neutrin0_consensus_types::proving::ProvingReport::from_certificate(
        chunk, validators, carried,
    )
    .ok_or(HistoryError::Evidence)?;
    proving
        .chunk_provers
        .extend(spec.pinned_chunk_prover(chunk.chunk_id));
    Ok((participation, proving))
}

/// Native `verify_carried_using` with a direct BLS verifier.
///
/// # Errors
/// Rejects a quorum or proposal that does not authenticate against `record`.
pub fn verify_carried(
    spec: &ChainSpec,
    record: &impl HistoricalSource,
    carried: &neutrin0_consensus_types::proving::CarriedCertificate,
) -> Result<
    (
        neutrin0_consensus_types::participation::ParticipationReport,
        neutrin0_consensus_types::proving::ProvingReport,
    ),
    HistoryError,
> {
    let mut verifier = crate::bls::DirectVerifier::default();
    verify_carried_using(
        spec.consensus_domain(),
        spec,
        record,
        carried,
        &mut verifier,
    )
}
