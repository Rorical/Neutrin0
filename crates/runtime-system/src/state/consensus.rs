//! Consensus-facing records: the candidate record consensus reads and the
//! certified participation the runtime consumes, with the absence lists and
//! acknowledgements liveness evidence is judged against.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use neutrin0_runtime_core::StateBackend;

use super::{
    PARTICIPATION_KEY, absent_key, prefixed_key, read_canonical, read_record, write_record,
};
use crate::Address;
use neutrin0_consensus_types::participation::{ParticipationReport, participation_commitment};
use neutrin0_consensus_types::runtime::{CONSENSUS_CANDIDATES_KEY, ConsensusCandidates};

/// Read the consensus-facing candidate record; absent state is empty.
pub fn load_consensus_candidates<B: StateBackend>(state: &mut B) -> ConsensusCandidates {
    read_record(state, CONSENSUS_CANDIDATES_KEY).unwrap_or_default()
}

pub(crate) fn store_consensus_candidates<B: StateBackend>(
    state: &mut B,
    candidates: &ConsensusCandidates,
) {
    write_record(state, CONSENSUS_CANDIDATES_KEY, candidates);
}

/// Read the latest participation report the runtime consumed, if any.
pub fn load_participation<B: StateBackend>(state: &mut B) -> Option<ParticipationReport> {
    read_record(state, PARTICIPATION_KEY)
}

/// Record a newer certified report and return the commitment the block
/// commits for its input. Reports arrive once per chunk and repeat in every
/// block from the chunk's carrier on, so only a strictly newer chunk writes.
/// A block before the carrier passes none and commits the latest report in
/// state (design 08).
///
/// The report's absence list is kept for as long as liveness evidence may
/// cite its chunk, the eight preceding chunks, so admission can charge only
/// validators the certified precommit left out.
pub(crate) fn apply_participation<B: StateBackend>(
    state: &mut B,
    report: Option<&ParticipationReport>,
) -> neutrin0_primitives::Hash {
    if let Some(report) = report
        && load_participation(state).is_none_or(|latest| latest.chunk_id < report.chunk_id)
    {
        write_record(state, PARTICIPATION_KEY, report);
        write_record(state, &absent_key(report.chunk_id), &report.absent);
        assert_eq!(
            report.absent.len(),
            report.absent_identities.len(),
            "absence identity coverage"
        );
        write_record(
            state,
            &prefixed_key(
                b"consensus:absent-identities:",
                &report.chunk_id.to_be_bytes(),
            ),
            &report.absent_identities,
        );
        if let Some(expired) = report
            .chunk_id
            .checked_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS)
        {
            state.delete(&absent_key(expired));
            state.delete(&prefixed_key(
                b"consensus:absent-identities:",
                &expired.to_be_bytes(),
            ));
            state.delete(&participation_ack_key(expired));
        }
    }
    report.map_or_else(
        || participation_commitment(load_participation(state).as_ref()),
        |report| participation_commitment(Some(report)),
    )
}

/// Gas for recording one authenticated positive participation identity.
pub(crate) const GAS_PARTICIPATION_ACK: u64 = 1_000;

fn participation_ack_key(chunk: u64) -> Vec<u8> {
    prefixed_key(b"consensus:participation-acks:", &chunk.to_be_bytes())
}

/// Whether an authenticated signature has corrected certificate-subset omission.
pub(crate) fn participation_acknowledged<B: StateBackend>(
    state: &mut B,
    chunk: u64,
    identity: &neutrin0_primitives::BlsPublicKey,
) -> bool {
    read_canonical::<Vec<neutrin0_primitives::BlsPublicKey>, _>(
        state,
        &participation_ack_key(chunk),
    )
    .is_some_and(|identities| identities.binary_search(identity).is_ok())
}

/// Apply authenticated positive participation before admitting any liveness claim.
pub(crate) fn apply_participation_acks<B: StateBackend>(
    state: &mut B,
    input: &neutrin0_runtime_abi::RuntimeBlockInput,
) -> u64 {
    let mut grouped =
        BTreeMap::<u64, alloc::collections::BTreeSet<neutrin0_primitives::BlsPublicKey>>::new();
    for ack in &input.participation_acks {
        grouped
            .entry(ack.chunk_id)
            .or_default()
            .insert(ack.identity);
    }
    for (chunk, additions) in grouped {
        let key = participation_ack_key(chunk);
        let identities = read_canonical::<Vec<neutrin0_primitives::BlsPublicKey>, _>(state, &key)
            .unwrap_or_default();
        assert!(
            identities.windows(2).all(|pair| pair[0] < pair[1]),
            "canonical acknowledged committee"
        );
        let mut merged: alloc::collections::BTreeSet<_> = identities.iter().copied().collect();
        merged.extend(additions);
        // A producer obligation: the input check bounds one block's
        // acknowledgements per chunk, and only committee seats are ever
        // acknowledged (the Chunk Guest refuses others), so an honest branch
        // never exceeds a committee. A body that does has no execution.
        assert!(
            merged.len() <= neutrin0_primitives::MAX_CONSENSUS_VALIDATORS,
            "bounded acknowledged committee"
        );
        let merged: Vec<_> = merged.into_iter().collect();
        if merged != identities {
            write_record(state, &key, &merged);
        }
    }
    u64::try_from(input.participation_acks.len()).expect("bounded participation acknowledgements")
        * GAS_PARTICIPATION_ACK
}

/// Economic absence requires a matured challenge window and no positive signature.
pub(crate) fn liveness_eligible<B: StateBackend>(
    state: &mut B,
    incoming_chunk: u64,
    source: u64,
    identity: &neutrin0_primitives::BlsPublicKey,
    address: &Address,
) -> bool {
    use neutrin0_consensus_types::participation::PARTICIPATION_CHALLENGE_CHUNKS;
    if source
        .checked_add(PARTICIPATION_CHALLENGE_CHUNKS)
        .is_none_or(|deadline| incoming_chunk <= deadline)
        || participation_acknowledged(state, source, identity)
    {
        return false;
    }
    let identities = read_canonical::<Vec<neutrin0_primitives::BlsPublicKey>, _>(
        state,
        &prefixed_key(b"consensus:absent-identities:", &source.to_be_bytes()),
    );
    let addresses = read_canonical::<Vec<Address>, _>(state, &absent_key(source));
    identities
        .zip(addresses)
        .is_some_and(|(identities, addresses)| {
            identities.len() == addresses.len()
                && identities
                    .iter()
                    .zip(addresses)
                    .any(|(key, account)| key == identity && &account == address)
        })
}
