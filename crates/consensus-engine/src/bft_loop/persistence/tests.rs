use super::*;
use crate::bft_loop::tests::{chain_spec_with, dummy_chunk, proposer, test_engine, test_engine_on};
use neutrin0_consensus_types::FinalityVoteData;
use neutrin0_storage::MemoryDatabase;

/// Owned reference encoding that [`SavedSessionRef`] must reproduce byte for byte.
fn owned_saved_session(engine: &Engine<MemoryDatabase>, session: &BftSession) -> SavedSession {
    SavedSession {
        spec: engine.chain_spec().hash(),
        chunk: session.chunk.clone(),
        validators: engine.active_validator_set().to_vec(),
        validator_root: engine.previous_validator_set_root().unwrap(),
        proof_hashes: session.proof_hashes.clone(),
        round: session.round(),
        round_started_at_secs: session.round_started_at_secs,
        prevote: session.current_vote(FinalityVotePhase::Prevote),
        precommit: session.current_vote(FinalityVotePhase::Precommit),
        local_identity: session.local_identity,
        local_votes: session.local_votes.clone(),
        highest_lock: session.highest_lock.clone(),
        prevote_justification: session.prevote_justification.clone(),
        pacemaker: session.pacemaker.clone(),
        proposal: session.proposal.clone(),
        valid_value: session.valid_value.clone(),
        candidates: session.candidates.clone(),
        selections: session.selections.clone(),
        local_nil_votes: session.local_nil_votes.clone(),
        nil_prevote: session
            .bft
            .current_nil_aggregate(FinalityVotePhase::Prevote),
        nil_precommit: session
            .bft
            .current_nil_aggregate(FinalityVotePhase::Precommit),
        round_certificate: session.round_certificate.clone(),
        local_round_report: session.local_round_report.clone(),
        pending_votes: session.bft.pending_votes(),
    }
}

#[test]
fn borrowed_session_encoding_is_the_owned_wire_format() {
    let spec = chain_spec_with(3);
    let base = spec.consensus.bft_round_timeout_base_secs;
    let mut engine = test_engine(spec.clone());
    engine.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    engine
        .open_authorized_bft_session_at(chunk.clone(), 0)
        .unwrap();
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        chunk_hash: chunk.hash(),
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let peer = proposer(1);
    let vote = FinalityVote {
        proof_manifests: Vec::new(),
        aggregation_bits: neutrin0_primitives::BitVec::from_bytes(3, vec![2]).unwrap(),
        signature: peer.sign_finality_vote(spec.consensus_domain(), &data),
        attestations: vec![peer.attest_vote(
            spec.consensus_domain(),
            data.clone(),
            Vec::new(),
            None,
        )],
        data,
    };
    engine.observe_finality_vote_at(vote, base - 1).unwrap();
    engine.tick_bft_round_timeouts(2 * base - 1).unwrap();
    let session = engine.bft_session(0).unwrap();
    assert!(session.proposal.is_some());
    assert!(session.highest_lock.is_some());
    assert!(session.valid_value.is_some());
    assert!(session.local_round_report.is_some());
    assert_eq!(session.local_votes.len(), 2);

    let owned = owned_saved_session(&engine, session);
    let owned = borsh::to_vec(&owned).unwrap();
    let borrowed = engine.encode_bft_session(session).unwrap();
    assert_eq!(borrowed, owned);
    let decoded: SavedSession = borsh::from_slice(&borrowed).unwrap();
    assert_eq!(borsh::to_vec(&decoded).unwrap(), owned);
    assert_eq!(
        engine
            .store()
            .db()
            .get(Column::BftSessions, &0_u64.to_be_bytes())
            .unwrap(),
        Some(borrowed)
    );
}

/// A validator moved to a fresh directory with its signing protection.
fn moved_validator() -> (
    neutrin0_primitives::ChainSpec,
    Engine<MemoryDatabase>,
    neutrin0_consensus_types::Chunk,
    MemoryDatabase,
) {
    let spec = chain_spec_with(3);
    let mut source = test_engine(spec.clone());
    source.set_local_voter(proposer(0));
    let chunk = dummy_chunk(0, spec.genesis_validator_set_root);
    source
        .open_authorized_bft_session_at(chunk.clone(), 0)
        .unwrap();
    let mut target = MemoryDatabase::new();
    crate::signing_transfer::SigningTransfer::export(source.store().db())
        .unwrap()
        .import(&mut target)
        .unwrap();
    (spec, source, chunk, target)
}

#[test]
fn a_moved_session_resumes_on_the_new_directory_and_across_restart() {
    let (spec, source, chunk, target) = moved_validator();
    let saved = source.bft_session(0).unwrap();
    let mut engine = test_engine_on(spec.clone(), target);
    engine.set_local_voter(proposer(0));
    engine.open_bft_session_at(chunk, 0).unwrap();
    let resumed = engine.bft_session(0).unwrap();
    assert_eq!(resumed.proposal, saved.proposal);
    assert_eq!(resumed.local_votes, saved.local_votes);
    assert_eq!(resumed.round(), saved.round());
    let restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(restarted.bft_session(0).unwrap().proposal, saved.proposal);
}

#[test]
fn a_session_ahead_of_finality_waits_bound_to_its_chain() {
    let (spec, _, _, mut target) = moved_validator();
    // Saved for a chunk this directory has not reached: kept, not refused.
    let bytes = target
        .get(Column::BftSessions, &0_u64.to_be_bytes())
        .unwrap()
        .unwrap();
    let mut ahead: SavedSession = borsh::from_slice(&bytes).unwrap();
    ahead.chunk.chunk_id = 3;
    target
        .delete(Column::BftSessions, &0_u64.to_be_bytes())
        .unwrap();
    target
        .put(
            Column::BftSessions,
            &3_u64.to_be_bytes(),
            &borsh::to_vec(&ahead).unwrap(),
        )
        .unwrap();
    let engine = test_engine_on(spec.clone(), target);
    let restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert!(restarted.bft_session(3).is_none());
    assert!(
        restarted
            .store()
            .db()
            .get(Column::BftSessions, &3_u64.to_be_bytes())
            .unwrap()
            .is_some()
    );
    // Another chain's genesis refuses the imported protection outright.
    let (_, _, _, imported) = moved_validator();
    assert!(Engine::genesis(chain_spec_with(4), imported).is_err());
}
