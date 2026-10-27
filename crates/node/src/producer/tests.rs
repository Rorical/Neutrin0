use super::*;

#[test]
fn a_producer_reserves_one_proof_slot_for_its_own_next_block() {
    assert_eq!(foreign_proof_slots(4, true), 3);
    assert_eq!(foreign_proof_slots(1, true), 0);
    assert_eq!(foreign_proof_slots(0, true), 0);
    // A prover that does not produce lends every slot to other candidates.
    assert_eq!(foreign_proof_slots(4, false), 4);
    assert_eq!(foreign_proof_slots(0, false), 0);
}

#[test]
fn chunk_proof_yields_to_pending_block_proofs_for_at_most_one_bound() {
    // Nothing pending or priority off: start immediately.
    assert!(!chunk_proof_deferred(true, false, 100, 4, 100));
    assert!(!chunk_proof_deferred(false, true, 100, 4, 100));
    // Pending block proofs defer the chunk proof inside the bound.
    assert!(chunk_proof_deferred(true, true, 100, 4, 100));
    assert!(chunk_proof_deferred(true, true, 100, 4, 103));
    // The bound ends the deferral whatever is still pending.
    assert!(!chunk_proof_deferred(true, true, 100, 4, 104));
    // A clock behind the certificate never underflows.
    assert!(chunk_proof_deferred(true, true, 100, 4, 90));
}

fn user_count(body: &neutrin0_consensus_types::Body) -> usize {
    body.transactions
        .iter()
        .filter(|bytes| {
            matches!(
                borsh::from_slice::<neutrin0_runtime_abi::RuntimeTransaction>(bytes),
                Ok(neutrin0_runtime_abi::RuntimeTransaction::User(_))
            )
        })
        .count()
}

#[test]
fn witness_backoff_preserves_mandatory_lanes_and_original_pool_payloads() {
    use neutrin0_consensus_types::{Body, FinalityVoteData, FinalityVotePhase};
    use neutrin0_runtime_abi::RuntimeTransaction;
    let system = vec![u8::MAX]; // An opaque non-user lane must remain untouched.
    let mut body = Body {
        transactions: (0..8)
            .map(|index| borsh::to_vec(&RuntimeTransaction::User(vec![index])).unwrap())
            .collect(),
        participation_acks: vec![neutrin0_consensus_types::participation::ParticipationVote {
            data: FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: [1; 32],
                selection: [0; 32],
                phase: FinalityVotePhase::Precommit,
            },
            validator_index: 0,
            vote_signature: [2; 96],
        }],
        ..Body::default()
    };
    body.transactions.insert(3, system.clone());
    let original = body.clone();
    let mut counts = Vec::new();
    let result: Result<usize, ProductionError<core::convert::Infallible>> =
        with_witness_backoff(&body, |candidate| {
            counts.push(user_count(&candidate));
            assert!(candidate.transactions.contains(&system));
            assert_eq!(candidate.participation_acks, original.participation_acks);
            assert_eq!(candidate.participation, original.participation);
            assert_eq!(candidate.programs, original.programs);
            assert_eq!(candidate.evidence_proofs, original.evidence_proofs);
            assert_eq!(candidate.artifacts, original.artifacts);
            if user_count(&candidate) > 0 {
                Err(ProductionError::WitnessTooLarge {
                    actual: 2_000,
                    limit: 1_000,
                })
            } else {
                Ok(candidate.transactions.len())
            }
        });
    assert_eq!(result.unwrap(), 1);
    assert_eq!(counts, vec![8, 4, 2, 0]);
    assert_eq!(body, original);
}

#[test]
fn witness_backoff_recognizes_wasm_size_guard_and_does_not_retry_other_failures() {
    use neutrin0_consensus_types::Body;
    use neutrin0_runtime_abi::RuntimeTransaction;
    let body = Body {
        transactions: vec![borsh::to_vec(&RuntimeTransaction::User(vec![1])).unwrap()],
        ..Body::default()
    };
    let mut counts = Vec::new();
    let result: Result<(), ProductionError<core::convert::Infallible>> =
        with_witness_backoff(&body, |candidate| {
            counts.push(user_count(&candidate));
            if user_count(&candidate) > 0 {
                Err(ProductionError::Executor(
                    "block proving input exceeds genesis limit".into(),
                ))
            } else {
                Ok(())
            }
        });
    assert!(result.is_ok());
    assert_eq!(counts, vec![1, 0]);
    let mut calls = 0;
    let result: Result<(), ProductionError<core::convert::Infallible>> =
        with_witness_backoff(&body, |_| {
            calls += 1;
            Err(ProductionError::Executor("invalid transaction".into()))
        });
    assert!(matches!(result, Err(ProductionError::Executor(_))));
    assert_eq!(calls, 1);
    calls = 0;
    let result: Result<(), ProductionError<core::convert::Infallible>> =
        with_witness_backoff(&body, |_| {
            calls += 1;
            Err(ProductionError::WitnessTooLarge {
                actual: 2_000,
                limit: 1_000,
            })
        });
    assert!(matches!(
        result,
        Err(ProductionError::WitnessTooLarge { .. })
    ));
    assert_eq!(calls, 4);
}

#[test]
fn dissemination_size_backoff_preserves_system_lanes_and_is_bounded() {
    use neutrin0_consensus_types::Body;
    use neutrin0_runtime_abi::RuntimeTransaction;
    let mut body = Body {
        transactions: (0..4)
            .map(|index| borsh::to_vec(&RuntimeTransaction::User(vec![index])).unwrap())
            .collect(),
        ..Body::default()
    };
    let system = vec![u8::MAX];
    body.transactions.insert(0, system.clone());
    let original = body.clone();
    let mut counts = Vec::new();
    let result: Result<(), ProductionError<core::convert::Infallible>> =
        with_witness_backoff(&body, |candidate| {
            assert!(candidate.transactions.contains(&system));
            counts.push(user_count(&candidate));
            if user_count(&candidate) > 1 {
                Err(ProductionError::BodyTooLarge {
                    actual: 9,
                    limit: 8,
                })
            } else {
                Ok(())
            }
        });
    assert!(result.is_ok());
    assert_eq!(counts, vec![4, 2, 1]);
    assert_eq!(body, original);
    let mut calls = 0;
    let result: Result<(), ProductionError<core::convert::Infallible>> =
        with_witness_backoff(&body, |_| {
            calls += 1;
            Err(ProductionError::BodyTooLarge {
                actual: 9,
                limit: 8,
            })
        });
    assert!(matches!(result, Err(ProductionError::BodyTooLarge { .. })));
    assert_eq!(calls, 4);
}

#[test]
fn current_slot_floors_from_genesis() {
    assert_eq!(current_slot(100, 4, 99), 0);
    assert_eq!(current_slot(100, 4, 100), 0);
    assert_eq!(current_slot(100, 4, 103), 0);
    assert_eq!(current_slot(100, 4, 104), 1);
    assert_eq!(current_slot(100, 4, 111), 2);
}

#[test]
fn preferred_prover_fallback_uses_durable_authenticated_start() {
    assert!(fallback_ready(true, 100, 15, 100));
    assert!(!fallback_ready(false, 100, 15, 114));
    assert!(fallback_ready(false, 100, 15, 115));
    assert!(fallback_ready(false, 100, 15, 200));
    assert!(fallback_ready(false, 100, 15, 99));
    assert!(fallback_ready(false, 100, 0, 99));
    assert!(!fallback_ready(false, u64::MAX, 15, u64::MAX));
}

#[test]
fn sleep_until_next_slot_targets_boundary() {
    assert_eq!(sleep_until_next_slot(100, 4, 99), Duration::from_secs(1));
    assert_eq!(sleep_until_next_slot(100, 4, 100), Duration::from_secs(4));
    assert_eq!(sleep_until_next_slot(100, 4, 101), Duration::from_secs(3));
    assert_eq!(sleep_until_next_slot(100, 4, 103), Duration::from_secs(1));
}
