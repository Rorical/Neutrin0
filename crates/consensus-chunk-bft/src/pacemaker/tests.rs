use super::*;

const fn test_domain() -> neutrin0_primitives::ConsensusDomain {
    neutrin0_primitives::ConsensusDomain::new(7, [1; 32])
}

fn validators() -> Vec<Validator> {
    (1..=4)
        .map(|byte| Validator {
            pubkey: neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[])
                .unwrap()
                .public_key()
                .to_bytes(),
            withdrawal_credentials: [0; 32],
            effective_stake: 100,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn report(index: u32, round: u32) -> RoundChange {
    let key =
        neutrin0_crypto::bls::SecretKey::key_gen(&[u8::try_from(index + 1).unwrap(); 32], &[])
            .unwrap();
    let mut report = RoundChange {
        chunk_id: 0,
        round,
        validator_index: index,
        highest_quorum: None,
        signature: [0; 96],
    };
    report.signature = key.sign(&report.signing_message(test_domain())).to_bytes();
    report
}

#[test]
fn missing_leader_runs_nil_phases_before_certified_next_round_and_backoff() {
    let mut clock = Pacemaker::new(0, 0, 10, 2, 3);
    assert_eq!(clock.on_timeout(11), None);
    assert_eq!(clock.on_timeout(12), Some(TimeoutAction::PrevoteNil));
    assert_eq!(clock.step(), RoundStep::Prevote);
    assert_eq!(clock.on_timeout(14), Some(TimeoutAction::PrecommitNil));
    assert_eq!(
        clock.on_timeout(16),
        Some(TimeoutAction::RoundChange { round: 1 })
    );
    assert_eq!(clock.on_timeout(17), None);
    assert_eq!(
        clock.on_timeout(18),
        Some(TimeoutAction::RoundChange { round: 1 })
    );
    let validators = validators();
    assert_eq!(
        clock
            .accept_round_change(test_domain(), &validators, (2, 3), report(0, 1))
            .unwrap(),
        None
    );
    assert_eq!(
        clock
            .accept_round_change(test_domain(), &validators, (2, 3), report(1, 1))
            .unwrap(),
        None
    );
    let cert = clock
        .accept_round_change(test_domain(), &validators, (2, 3), report(2, 1))
        .unwrap()
        .unwrap();
    assert_eq!(cert.reports.len(), 3);
    assert_eq!(clock.round(), 0);
    clock.advance_round(cert.round, 18).unwrap();
    assert_eq!(clock.step(), RoundStep::Propose);
    assert_eq!(clock.deadline(), 23);
    assert_eq!(
        clock.advance_round(0, 18),
        Err(BftError::RoundNotIncreased {
            current: 1,
            requested: 0
        })
    );
}

#[test]
fn nil_precommit_quorum_ends_old_phases_without_postponing_reports() {
    let mut clock = Pacemaker::new(0, 0, 10, 2, 3);
    clock.enter_await_round(11);
    assert_eq!(clock.step(), RoundStep::AwaitRound);
    assert_eq!(clock.deadline(), 13);
    clock.enter_prevote(12);
    clock.enter_precommit(12);
    clock.enter_await_round(12);
    assert_eq!(clock.step(), RoundStep::AwaitRound);
    assert_eq!(clock.deadline(), 13);
    assert_eq!(clock.on_timeout(12), None);
    assert_eq!(
        clock.on_timeout(13),
        Some(TimeoutAction::RoundChange { round: 1 })
    );
    assert_eq!(clock.round(), 0);
}

#[test]
fn exact_durable_phase_and_reports_roundtrip_and_are_reauthenticated() {
    let validators = validators();
    let mut clock = Pacemaker::new(0, 2, 10, 2, 3);
    clock.enter_prevote(11);
    clock
        .accept_round_change(test_domain(), &validators, (2, 3), report(0, 3))
        .unwrap();
    let restored: Pacemaker = borsh::from_slice(&borsh::to_vec(&clock).unwrap()).unwrap();
    assert_eq!(restored, clock);
    assert!(restored.context_matches(0, 2, 2, 3));
    assert!(!restored.context_matches(1, 2, 2, 3));
    assert_eq!(
        restored.validate_saved_reports(test_domain(), &validators, (2, 3)),
        Ok(())
    );
    assert!(
        restored
            .validate_saved_reports(
                neutrin0_primitives::ConsensusDomain {
                    chain_id: 8,
                    ..test_domain()
                },
                &validators,
                (2, 3)
            )
            .is_err()
    );
    let mut bad = restored;
    bad.reports
        .get_mut(&3)
        .unwrap()
        .get_mut(&0)
        .unwrap()
        .signature[0] ^= 1;
    assert!(
        bad.validate_saved_reports(test_domain(), &validators, (2, 3))
            .is_err()
    );
}

#[test]
fn replayed_old_report_and_single_attacker_cannot_authenticate_round_catchup() {
    let validators = validators();
    let mut clock = Pacemaker::new(0, 1, 10, 2, 3);
    assert_eq!(
        clock.accept_round_change(test_domain(), &validators, (2, 3), report(0, 1)),
        Err(BftError::WrongVoteTarget)
    );
    for round in 2..20 {
        assert_eq!(
            clock
                .accept_round_change(test_domain(), &validators, (2, 3), report(0, round))
                .unwrap(),
            None
        );
    }
    assert_eq!(clock.round(), 1);
    assert_eq!(clock.reports.len(), 2);
    clock
        .accept_round_change(test_domain(), &validators, (2, 3), report(1, 2))
        .unwrap();
    assert!(
        clock
            .accept_round_change(test_domain(), &validators, (2, 3), report(2, 2))
            .unwrap()
            .is_some()
    );
}
