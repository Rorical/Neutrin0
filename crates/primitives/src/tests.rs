use super::*;

#[test]
fn proving_input_allocation_limit_is_positive_bounded_and_domain_bound() {
    let mut spec = test_chain_spec();
    let hash = spec.hash();
    spec.proof.max_block_proving_input_bytes += 1;
    assert_ne!(spec.hash(), hash);
    assert!(spec.validate().is_ok());
    spec.proof.max_block_proving_input_bytes = 0;
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::InvalidBlockProvingInputLimit)
    );
    spec.proof.max_block_proving_input_bytes = MAX_BLOCK_PROVING_INPUT_BYTES + 1;
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::InvalidBlockProvingInputLimit)
    );
}

#[test]
fn consensus_domain_binds_complete_spec_and_has_one_exact_prefix() {
    let spec = test_chain_spec();
    let domain = spec.consensus_domain();
    assert_eq!(domain.chain_id, spec.chain_id);
    assert_eq!(domain.chain_spec_hash, spec.hash());
    let message = domain.signing_message(DOMAIN_PREVOTE, &[7, 9]);
    assert_eq!(message.len(), 58);
    assert_eq!(&message[..16], &DOMAIN_PREVOTE);
    assert_eq!(&message[16..24], &spec.chain_id.to_le_bytes());
    assert_eq!(&message[24..56], &spec.hash());
    assert_eq!(&message[56..], &[7, 9]);
    let mut other = spec;
    other.consensus.bft_round_timeout_base_secs += 1;
    assert_eq!(domain.chain_id, other.consensus_domain().chain_id);
    assert_ne!(
        domain.chain_spec_hash,
        other.consensus_domain().chain_spec_hash
    );
}

#[test]
fn borsh_signing_message_matches_the_encoded_payload_form() {
    let domain = test_chain_spec().consensus_domain();
    let payload = (7_u64, [3_u8; 32], alloc::vec![1_u8, 2, 3], Some(9_u32));
    assert_eq!(
        domain.signing_message_borsh(DOMAIN_PREVOTE, &payload),
        domain.signing_message(DOMAIN_PREVOTE, &borsh::to_vec(&payload).unwrap())
    );
    assert_eq!(
        domain.signing_message_borsh(DOMAIN_BFT_NIL, &()),
        domain.signing_message(DOMAIN_BFT_NIL, &[])
    );
}

fn forked_spec() -> ChainSpec {
    let mut spec = test_chain_spec();
    let chunk_size = spec.consensus.chunk_size;
    spec.fork = Some(alloc::boxed::Box::new(ForkAnchor {
        predecessor: [9; 32],
        count: 5,
        endpoint_programs: ProgramSet {
            runtime_code_hash: [10; 32],
            execution: ExecutionPrograms {
                fact: [10; 8],
                evidence: [11; 8],
                block: [12; 8],
            },
        },
        start: ConsensusBoundary {
            next_chunk_id: 5,
            height: 5 * chunk_size,
            programs: spec.genesis_programs(),
            ..ConsensusBoundary::default()
        },
        endpoint_prover: runtime_account([13; 20]),
        prior_domains: vec![
            PriorDomain {
                chain_spec_hash: [8; 32],
                end_chunk: 2,
                end_height: 2 * chunk_size,
            },
            PriorDomain {
                chain_spec_hash: [9; 32],
                end_chunk: 5,
                end_height: 5 * chunk_size,
            },
        ],
    }));
    spec
}

#[test]
fn a_fork_carries_its_predecessors_last_certificate_without_ratifying_its_proof() {
    let spec = forked_spec();
    spec.validate().unwrap();
    // The fork's first chunk carries chunk 4's certificate but ratifies
    // nothing; the endpoint prover is credited for chunk 4 instead.
    assert_eq!(spec.carried_chunk(5), Some(4));
    assert_eq!(spec.previous_chunk(5), None);
    assert_eq!(
        spec.pinned_chunk_prover(5),
        Some((4, runtime_account([13; 20])))
    );
    assert_eq!(spec.pinned_chunk_prover(6), None);
    assert_eq!(spec.carried_chunk(0), None);
    // A carried pre-fork certificate ratifies under its own
    // specification: each predecessor's first chunk ratifies nothing.
    let domain = spec.consensus_domain();
    let ratified: Vec<_> = (0..7).map(|chunk| domain.previous_chunk(chunk)).collect();
    assert_eq!(
        ratified,
        [None, Some(0), None, Some(2), Some(3), None, Some(5)]
    );
}

#[test]
fn signatures_on_older_chunks_use_the_domain_in_force_at_them() {
    let spec = forked_spec();
    spec.validate().unwrap();
    let domain = spec.consensus_domain();
    let chunk_size = spec.consensus.chunk_size;
    assert_eq!(domain.first_chunk(), 5);
    assert_eq!(spec.first_chunk(), 5);
    assert_eq!(spec.previous_chunk(5), None);
    assert_eq!(spec.previous_chunk(6), Some(5));
    assert_eq!(domain.at_chunk(0).chain_spec_hash, [8; 32]);
    assert_eq!(domain.at_chunk(1).chain_spec_hash, [8; 32]);
    assert_eq!(domain.at_chunk(2).chain_spec_hash, [9; 32]);
    assert_eq!(domain.at_chunk(4).chain_spec_hash, [9; 32]);
    assert_eq!(domain.at_chunk(5), domain);
    assert_eq!(domain.at_height(2 * chunk_size).chain_spec_hash, [8; 32]);
    assert_eq!(
        domain.at_height(2 * chunk_size + 1).chain_spec_hash,
        [9; 32]
    );
    assert_eq!(domain.at_height(5 * chunk_size + 1), domain);
    // A historical domain signs exactly the predecessor's prefix.
    assert_eq!(
        &domain.at_chunk(3).signing_message(DOMAIN_PREVOTE, &[])[24..56],
        &[9; 32]
    );
    // Without a fork every chunk uses the one current domain.
    let genesis = test_chain_spec().consensus_domain();
    assert_eq!(genesis.first_chunk(), 0);
    assert_eq!(genesis.at_chunk(0), genesis);
}

#[test]
fn the_endpoint_names_the_fork_scheduled_for_the_successors_programs() {
    let spec = forked_spec();
    let fork = spec.fork.as_deref().unwrap();
    let endpoint = spec.fork_endpoint().unwrap();
    assert_eq!(endpoint.programs, fork.endpoint_programs);
    assert_eq!(
        endpoint.fork,
        Some(ScheduledFork {
            count: 5,
            successor: spec.pinned_programs().commitment(),
        })
    );
    // The endpoint proves nothing further; its successor's start does.
    assert!(endpoint.proves(4) && !endpoint.proves(5));
    assert_eq!(ConsensusBoundary::fork_start(&endpoint, &spec), fork.start);
    assert!(fork.start.proves(5));
    // Other successor programs would name another endpoint.
    let mut other = spec.clone();
    other.genesis_artifacts.chunk = [0xAB; 32];
    assert_ne!(other.fork_endpoint(), Some(endpoint));
    assert_eq!(test_chain_spec().fork_endpoint(), None);
}

#[test]
fn fork_anchor_must_end_with_its_predecessor_at_the_count() {
    for change in [
        (|fork: &mut ForkAnchor| fork.count = 4) as fn(&mut ForkAnchor),
        |fork| fork.predecessor = [1; 32],
        |fork| fork.start.next_chunk_id = 4,
        |fork| fork.start.programs.runtime_code_hash = [1; 32],
        |fork| fork.endpoint_programs.execution.block = [0; 8],
        |fork| fork.endpoint_prover = [1; 32],
        |fork| fork.prior_domains.clear(),
        |fork| fork.prior_domains[0].end_chunk = 5,
        |fork| fork.prior_domains[1].end_height += 1,
        |fork| fork.prior_domains = vec![fork.prior_domains[1]; MAX_PRIOR_DOMAINS + 1],
        |fork| {
            fork.start.fork = Some(ScheduledFork {
                count: 5,
                successor: [1; 32],
            });
        },
    ] {
        let mut spec = forked_spec();
        change(spec.fork.as_mut().unwrap());
        assert_eq!(spec.validate(), Err(ChainSpecError::InvalidFork));
    }
    let mut spec = forked_spec();
    spec.genesis_chunk = [0; 8];
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::IncompleteGenesisPrograms)
    );
}

#[test]
fn exactly_two_thirds_is_never_a_quorum() {
    // Three equal seats: two signers hold exactly two thirds. Two such
    // quorums overlap in one seat, so one faulty seat could finalize both.
    assert!(!quorum_reached(2, 3, 2, 3));
    assert!(quorum_reached(3, 3, 2, 3));
    assert!(!quorum_reached(4, 6, 2, 3));
    assert!(quorum_reached(5, 6, 2, 3));
    assert!(quorum_reached(67, 100, 2, 3));
    assert!(!quorum_reached(u128::MAX / 3 * 2, u128::MAX / 3 * 3, 2, 3));
    assert!(quorum_reached(u128::MAX, u128::MAX, u64::MAX, u64::MAX));
    assert!(!quorum_reached(
        u128::MAX - 1,
        u128::MAX,
        u64::MAX,
        u64::MAX
    ));
    // A higher configured fraction still applies on top.
    assert!(!quorum_reached(70, 100, 3, 4));
    assert!(quorum_reached(75, 100, 3, 4));
    // Unanimity under a unit fraction.
    assert!(quorum_reached(7, 7, 1, 1));
    assert!(!quorum_reached(6, 7, 1, 1));
}

#[test]
fn wide_arithmetic_is_exact_across_u128() {
    assert_eq!(widening_mul(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
    assert_eq!(widening_mul(u128::MAX, 2), (1, u128::MAX - 1));
    assert_eq!(widening_mul(1 << 64, 1 << 64), (1, 0));
    assert_eq!(
        mul_div_floor(u128::MAX, u128::MAX, u128::MAX),
        Some(u128::MAX)
    );
    assert_eq!(mul_div_floor(u128::MAX, 3, 4), Some(u128::MAX / 4 * 3 + 2));
    assert_eq!(mul_div_floor(10, 7, 3), Some(23));
    assert_eq!(mul_div_floor(u128::MAX, 2, 1), None);
    assert_eq!(mul_div_floor(1, 1, 0), None);
    // A pro-rata share of a whole-token pool by 32-token stakes.
    let pool = 1_000 * WEI_PER_TOKEN;
    let stake = 32 * WEI_PER_TOKEN;
    assert_eq!(mul_div_floor(pool, stake, 3 * stake), Some(pool / 3));
}

#[test]
fn quorum_helpers_match_the_widened_reference_arithmetic() {
    let samples = [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        u64::MAX / 3,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ];
    for numerator in samples {
        for denominator in samples {
            let (n, d) = (u128::from(numerator), u128::from(denominator));
            let valid = d != 0 && n != 0 && n <= d && n * 3 >= d * 2;
            assert_eq!(quorum_fraction_valid(numerator, denominator), valid);
            for stake in samples {
                for total in samples {
                    let (s, t) = (u128::from(stake), u128::from(total));
                    let expected = s * 3 > t * 2 && s * d >= t * n;
                    let actual = quorum_reached(s, t, numerator, denominator);
                    assert_eq!(actual, expected);
                }
            }
        }
    }
}

#[test]
fn in_place_merkle_matches_reference_for_every_tree_shape() {
    // Independent level-allocating reference, including all odd promotions.
    for count in 0..130 {
        let mut reference: Vec<Hash> = (0_u32..count)
            .map(|i| blake3_256(&i.to_le_bytes()))
            .collect();
        let actual = merkle_root_from_hashes(reference.clone());
        while reference.len() > 1 {
            reference = reference
                .chunks(2)
                .map(|pair| {
                    if pair.len() == 1 {
                        return pair[0];
                    }
                    let mut bytes = [0; 64];
                    bytes[..32].copy_from_slice(&pair[0]);
                    bytes[32..].copy_from_slice(&pair[1]);
                    blake3_256(&bytes)
                })
                .collect();
        }
        assert_eq!(
            actual,
            reference.first().copied().unwrap_or(EMPTY_MERKLE_ROOT)
        );
    }
}

#[test]
fn domain_tags_are_exactly_sixteen_bytes() {
    let tags = [
        DOMAIN_VRF,
        DOMAIN_PROPOSER_SIG,
        DOMAIN_PREVOTE,
        DOMAIN_PRECOMMIT,
        DOMAIN_VOTE_ATTESTATION,
        DOMAIN_BFT_PROPOSAL,
        DOMAIN_BFT_NIL,
        DOMAIN_BFT_NIL_ATTESTATION,
        DOMAIN_BFT_ROUND_CHANGE,
        DOMAIN_DA_PUBLICATION,
        DOMAIN_DEPOSIT_POP,
        DOMAIN_AGG_PROOF,
        DOMAIN_CHECKPOINT,
        DOMAIN_HISTORY_LEAF,
        DOMAIN_HISTORY_NODE,
        DOMAIN_HISTORY_ROOT,
        DOMAIN_TX_LEAF,
        DOMAIN_TX_NODE,
        DOMAIN_TX_ROOT,
    ];

    for tag in tags {
        assert_eq!(tag.len(), 16);
    }
    let distinct: alloc::collections::BTreeSet<_> = tags.iter().collect();
    assert_eq!(distinct.len(), tags.len());
}

#[test]
fn a_transaction_root_names_one_list_of_one_shape() {
    let leaves: Vec<_> = [b"a".as_slice(), b"b", b"c"]
        .iter()
        .map(|blob| transaction_leaf(blob))
        .collect();
    let root = transactions_root(leaves.clone());
    assert_eq!(
        root,
        transactions_root_of_blobs(&[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()])
    );
    // The first two leaves folded into one entry: an untagged, uncounted
    // tree gives that list the same root; this one does not.
    let mut node = blake3::Hasher::new();
    node.update(&DOMAIN_TX_NODE);
    node.update(&leaves[0]);
    node.update(&leaves[1]);
    let folded = alloc::vec![*node.finalize().as_bytes(), leaves[2]];
    assert_ne!(transactions_root(folded), root);
    assert_ne!(
        transactions_root(Vec::new()),
        transactions_root(alloc::vec![ZERO_HASH])
    );
}

#[test]
fn bounded_bytes_rejects_oversized_input() {
    let result = BoundedBytes::<2>::new(vec![1, 2, 3]);
    assert!(matches!(result, Err(BoundsError { actual: 3, max: 2 })));
    let error = borsh::from_slice::<BoundedBytes<2>>(&3_u32.to_le_bytes()).unwrap_err();
    assert_eq!(error.kind(), borsh::io::ErrorKind::InvalidData);
    assert!(borsh::from_slice::<BoundedBytes<2>>(&[2, 0, 0, 0, 1]).is_err());
}

#[test]
fn bit_vec_round_trips_and_rejects_padding() {
    let mut bits = BitVec::default();
    bits.push(true);
    bits.push(false);
    bits.push(true);

    let encoded = borsh::to_vec(&bits).expect("borsh serialization succeeds");
    let decoded = borsh::from_slice::<BitVec>(&encoded).expect("valid bit vec decodes");
    assert_eq!(decoded.get(0), Some(true));
    assert_eq!(decoded.get(1), Some(false));
    assert_eq!(decoded.get(2), Some(true));
    assert_eq!(decoded.get(3), None);

    let invalid = BitVec::from_bytes(3, vec![0b1111_1000]);
    assert!(invalid.is_err());
}

#[test]
fn chain_spec_validates_genesis_validator_root() {
    let spec = test_chain_spec();
    assert_eq!(spec.validate(), Ok(()));
    assert_ne!(spec.hash(), ZERO_HASH);
}

#[test]
fn bft_phase_deadlines_and_eventual_synchrony_backoff_must_be_positive() {
    for backoff in [false, true] {
        let mut spec = test_chain_spec();
        if backoff {
            spec.consensus.bft_round_timeout_step_secs = 0;
        } else {
            spec.consensus.bft_round_timeout_base_secs = 0;
        }
        assert_eq!(spec.validate(), Err(ChainSpecError::ZeroConsensusParameter));
    }
}

#[test]
fn both_bft_quorums_require_at_least_two_thirds_without_overflow() {
    for (numerator, denominator, valid) in [
        (0, 3, false),
        (1, 0, false),
        (1, 3, false),
        (1, 2, false),
        (3, 5, false),
        (2, 3, true),
        (4, 6, true),
        (3, 4, true),
        (1, 1, true),
        (4, 3, false),
        (u64::MAX / 3, u64::MAX, false),
        (u64::MAX - 1, u64::MAX, true),
    ] {
        for precommit in [false, true] {
            let mut spec = test_chain_spec();
            if precommit {
                spec.consensus.bft_precommit_quorum_numerator = numerator;
                spec.consensus.bft_precommit_quorum_denominator = denominator;
            } else {
                spec.consensus.bft_prevote_quorum_numerator = numerator;
                spec.consensus.bft_prevote_quorum_denominator = denominator;
            }
            assert_eq!(
                spec.validate(),
                if valid {
                    Ok(())
                } else {
                    Err(ChainSpecError::InvalidQuorum)
                },
                "quorum {numerator}/{denominator}, precommit={precommit}",
            );
        }
    }
}

#[test]
fn evidence_policy_requires_a_usable_window_bounded_queue_and_throughput() {
    type Mutation = fn(&mut RuntimeParams);
    for mutate in [
        |p: &mut RuntimeParams| p.evidence_max_age_blocks = 0,
        |p: &mut RuntimeParams| p.evidence_max_pending = 0,
        |p: &mut RuntimeParams| p.evidence_max_pending = 4097,
        |p: &mut RuntimeParams| p.evidence_admissions_per_block = 0,
        |p: &mut RuntimeParams| p.evidence_executions_per_block = 0,
        |p: &mut RuntimeParams| p.evidence_executions_per_block = p.evidence_max_pending + 1,
        |p: &mut RuntimeParams| p.evidence_max_age_blocks = p.unbonding_delay_blocks,
    ] as [Mutation; 7]
    {
        let mut spec = test_chain_spec();
        mutate(&mut spec.runtime);
        assert_eq!(spec.validate(), Err(ChainSpecError::InvalidEvidencePolicy));
    }
    // The unbonding delay must exceed one chunk so a zero stake is seen at
    // a boundary before any record can be retired. Shrink the exit delay
    // first so the collateral rule does not mask the evidence rule.
    let mut spec = test_chain_spec();
    spec.consensus.exit_delay_epochs = 1;
    spec.consensus.epoch_length_in_chunks = 1;
    spec.runtime.evidence_max_age_blocks = 1;
    spec.runtime.unbonding_delay_blocks = spec.consensus.chunk_size;
    assert_eq!(spec.validate(), Err(ChainSpecError::InvalidEvidencePolicy));
    spec.runtime.unbonding_delay_blocks += 1;
    // A shorter unbonding delay also shrinks the admissible trust window.
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::WeakSubjectivityOutlivesAccountability)
    );
    spec.light_client.weak_subjectivity_period_secs =
        spec.runtime.unbonding_delay_blocks * spec.consensus.slot_duration_secs;
    // The exiting seat still signs for two chunks after its exit delay.
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::ExitDelayOutlivesCollateral)
    );
    spec.runtime.unbonding_delay_blocks = 3 * spec.consensus.chunk_size;
    assert_eq!(spec.validate(), Ok(()));
}

#[test]
fn validator_stake_has_a_positive_floor_and_market_shares_are_bounded() {
    let mut spec = test_chain_spec();
    assert!(spec.runtime.min_validator_stake > 0);
    spec.runtime.min_validator_stake = 0;
    assert_eq!(spec.validate(), Err(ChainSpecError::ZeroMinValidatorStake));
    let mut spec = test_chain_spec();
    spec.runtime.chunk_prover_fee_bps = 10_001;
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::InvalidProofMarketPolicy)
    );
    let mut spec = test_chain_spec();
    spec.runtime.annual_issuance_bps = 10_001;
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::InvalidProofMarketPolicy)
    );
}

#[test]
fn weak_subjectivity_window_cannot_outlive_unbonding() {
    let mut spec = test_chain_spec();
    let unbonding_secs = spec.runtime.unbonding_delay_blocks * spec.consensus.slot_duration_secs;
    spec.light_client.weak_subjectivity_period_secs = unbonding_secs;
    assert_eq!(spec.validate(), Ok(()));
    spec.light_client.weak_subjectivity_period_secs = unbonding_secs + 1;
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::WeakSubjectivityOutlivesAccountability)
    );
    // Lengthening the unbonding delay restores the longer trust window;
    // the liveness window still has to stay strictly inside it.
    spec.runtime.unbonding_delay_blocks += 1;
    assert_eq!(spec.validate(), Ok(()));
    spec.runtime.evidence_max_age_blocks = spec.runtime.unbonding_delay_blocks;
    assert_eq!(spec.validate(), Err(ChainSpecError::InvalidEvidencePolicy));
}

#[test]
fn chain_spec_bounds_the_genesis_weight_total() {
    let mut spec = test_chain_spec();
    let mut second = spec.initial_validators[0].clone();
    second.pubkey = [8; 48];
    second.effective_stake = MAX_TOTAL_STAKE - spec.initial_validators[0].effective_stake;
    spec.initial_validators.push(second);
    spec.genesis_validator_set_root = crate::validators_root(&spec.initial_validators);
    assert_eq!(spec.validate(), Ok(()));
    spec.initial_validators[1].effective_stake += 1;
    spec.genesis_validator_set_root = crate::validators_root(&spec.initial_validators);
    let result = spec.validate();
    assert_eq!(result, Err(ChainSpecError::ValidatorStakeOverflow));
}

#[test]
fn chain_spec_rejects_noncanonical_genesis_validator_root() {
    let mut spec = test_chain_spec();
    spec.genesis_validator_set_root = [99; 32];
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::InvalidGenesisValidatorRoot)
    );
}

#[test]
fn committee_bounds_and_identity_uniqueness_are_consensus_constraints() {
    assert!(committee_size_valid(256, 64));
    assert!(!committee_size_valid(257, 1));
    assert!(!committee_size_valid(256, 65));
    assert!(!committee_size_valid(1, 0));
    let mut duplicate = test_chain_spec();
    duplicate
        .initial_validators
        .push(duplicate.initial_validators[0].clone());
    duplicate.genesis_validator_set_root = crate::validators_root(&duplicate.initial_validators);
    assert_eq!(
        duplicate.validate(),
        Err(ChainSpecError::DuplicateValidatorIdentity)
    );
    let mut oversized = test_chain_spec();
    oversized.initial_validators = vec![oversized.initial_validators[0].clone(); 257];
    assert_eq!(oversized.validate(), Err(ChainSpecError::CommitteeBounds));
}

#[test]
fn wide_remainder_reduces_the_whole_digest_exactly() {
    let mut value = [0; 32];
    value[31] = 200;
    assert_eq!(wide_remainder(&value, 7), Some(200 % 7));
    assert_eq!(wide_remainder(&value, 0), None);
    // 2^128 + 5 needs the high half: modulo 2^127 + 1 it is
    // 2^128 - 2 * (2^127 + 1) + 5 + 2 = 3.
    let mut value = [0; 32];
    value[15] = 1;
    value[31] = 5;
    assert_eq!(wide_remainder(&value, (1 << 127) + 1), Some(3));
    // The largest digest under the largest modulus.
    assert_eq!(wide_remainder(&[0xff; 32], u128::MAX), Some(0));
    assert_eq!(
        wide_remainder(&[0xff; 32], 1 << 64),
        Some(u128::from(u64::MAX))
    );
}

#[test]
fn exit_handoff_cannot_outlive_slashable_collateral() {
    let mut spec = test_chain_spec();
    let interval = spec.consensus.epoch_length_in_chunks * spec.consensus.chunk_size;
    spec.consensus.exit_delay_epochs = spec.runtime.unbonding_delay_blocks.div_ceil(interval);
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::ExitDelayOutlivesCollateral)
    );
    // An exiting seat signs the chunk its exit takes effect after, and
    // that signature finalizes a chunk later: one block short of both is
    // refused even though it outlasts the exit delay itself.
    let mut spec = test_chain_spec();
    let exit = spec.consensus.exit_delay_epochs * interval;
    let bound = spec.consensus.exit_accountability_blocks().unwrap();
    assert_eq!(bound, exit + 2 * spec.consensus.chunk_size);
    spec.runtime.evidence_max_age_blocks = 1;
    spec.runtime.unbonding_delay_blocks = bound - 1;
    spec.light_client.weak_subjectivity_period_secs =
        (bound - 1) * spec.consensus.slot_duration_secs;
    assert!(spec.runtime.unbonding_delay_blocks > exit);
    assert_eq!(
        spec.validate(),
        Err(ChainSpecError::ExitDelayOutlivesCollateral)
    );
    spec.runtime.unbonding_delay_blocks = bound;
    assert_eq!(spec.validate(), Ok(()));
}

fn test_chain_spec() -> ChainSpec {
    let consensus = ConsensusParams::default();
    let proof = ProofParams::default();
    let mut spec = ChainSpec {
        genesis_execution: ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"local-testnet".to_vec()).expect("name fits"),
        chain_id: 7,
        genesis_time: 1_800_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [4; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [5; 32],
        genesis_state_root: [2; 32],
        genesis_block_hash: [1; 32],
        genesis_validator_set_root: [3; 32],
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: vec![Validator {
            pubkey: [6; 48],
            withdrawal_credentials: crate::runtime_account([7; 20]),
            effective_stake: DEFAULT_MIN_VALIDATOR_STAKE,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }],
        metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
    };
    spec.genesis_validator_set_root = crate::validators_root(&spec.initial_validators);
    spec
}
